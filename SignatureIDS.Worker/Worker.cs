using SignatureIDS.Core.DTO.Detection;
using SignatureIDS.Core.ServiceContracts;
using System.Threading.Channels;

namespace SignatureIDS.Worker
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly IRulesSyncService _rulesSync;
        private readonly IPacketCaptureService _capture;
        private readonly ISignatureDetectionService _detection;
        private readonly IAlertDispatcherService _alertDispatcher;
        private readonly IFlowFeatureExtractor _featureExtractor;
        private readonly ICsvSerializer _csvSerializer;
        private readonly IMlForwarderService _mlForwarder;
        private readonly IConfiguration _config;

        private readonly Channel<PacketHeaders> _channel = Channel.CreateUnbounded<PacketHeaders>();

        private readonly List<PacketHeaders> _mlBuffer = [];
        private DateTime _bufferStart = DateTime.UtcNow;
        private const int MlWindowSeconds = 8;

        public Worker(ILogger<Worker> logger,
            IRulesSyncService rulesSync,
            IPacketCaptureService capture,
            ISignatureDetectionService detection,
            IAlertDispatcherService alertDispatcher,
            IFlowFeatureExtractor featureExtractor,
            ICsvSerializer csvSerializer,
            IMlForwarderService mlForwarder,
            IConfiguration config)
        {
            _logger = logger;
            _rulesSync = rulesSync;
            _capture = capture;
            _detection = detection;
            _alertDispatcher = alertDispatcher;
            _featureExtractor = featureExtractor;
            _csvSerializer = csvSerializer;
            _mlForwarder = mlForwarder;
            _config = config;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Syncing rules...");
            await _rulesSync.SyncNowAsync(stoppingToken);
            _logger.LogInformation("Rules synced.");

            var iface = _config["Capture:Interface"] ?? throw new Exception("Capture:Interface config value is required");

            _capture.StartCapture(iface, packet => _channel.Writer.TryWrite(packet));
            _logger.LogInformation("Packet capture started on interface {Interface}", iface);

            await foreach (var packet in _channel.Reader.ReadAllAsync(stoppingToken))
            {
                var result = await _detection.DetectAsync(packet);

                if (result is { IsMatch: true, MatchedRule: not null })
                {
                    var rule = result.MatchedRule;
                    var alert = new Alert
                    {
                        Timestamp = packet.Timestamp,
                        Sid = rule.Sid,
                        Msg = rule.Msg,
                        SrcIp = packet.SrcIp,
                        DstIp = packet.DstIp,
                        SrcPort = packet.SrcPort,
                        DstPort = packet.DstPort,
                        Protocol = packet.Protocol,
                        DetectionSource = "Signature"
                    };

                    await _alertDispatcher.SendAsync(alert);
                    _logger.LogInformation("Alert dispatched for SID {Sid}: {Msg} {SrcIp} -> {DstIp}", rule.Sid, rule.Msg, alert.SrcIp, alert.DstIp);
                }
                else
                {
                    _mlBuffer.Add(packet);
                }

                if ((DateTime.UtcNow - _bufferStart).TotalSeconds >= MlWindowSeconds)
                {
                    if (_mlBuffer.Count > 0)
                    {
                        var features = _featureExtractor.Extract(_mlBuffer);
                        var csv = _csvSerializer.WriteRow(features);
                        var mlResult = await _mlForwarder.ForwardAsync(csv);

                        if (mlResult.IsAttack && mlResult.Alert is not null)
                        {
                            mlResult.Alert.DetectionSource = "ML";
                            await _alertDispatcher.SendAsync(mlResult.Alert);
                            _logger.LogWarning("ML alert: {AttackType} {SrcIp} -> {DstIp}",
                                mlResult.AttackType, mlResult.Alert.SrcIp, mlResult.Alert.DstIp);
                        }
                    }

                    _mlBuffer.Clear();
                    _bufferStart = DateTime.UtcNow;
                }
            }
        }
    }
}
