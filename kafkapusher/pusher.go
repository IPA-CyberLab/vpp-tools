package kafkapusher

import (
	"context"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type KafkaPusher struct {
	kc     *kgo.Client
	ktopic string
	logger *zap.Logger
}

func New(name, broker, topic string, logger *zap.Logger) (*KafkaPusher, error) {
	s := logger.Named("kafkapusher.New").Sugar()

	kc, err := kgo.NewClient(kgo.SeedBrokers(broker))
	if err != nil {
		return nil, err
	}

	// try producing a message to catch easy errors
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := kc.ProduceSync(ctx, &kgo.Record{
		Topic: topic,
		Value: []byte(fmt.Sprintf(`{"info": "%s started"}`, name)),
	})
	if err := r.FirstErr(); err != nil {
		return nil, fmt.Errorf("failed to produce initial message to Kafka: %w", err)
	}
	s.Info("Successfully produced initial message to Kafka.")

	return &KafkaPusher{
		kc:     kc,
		ktopic: topic,
		logger: logger,
	}, nil
}

func (kp *KafkaPusher) Close() {
	s := kp.logger.Named("kafkapusher.Close").Sugar()
	s.Info("Closing Kafka client")
	kp.kc.Close()
	s.Info("Kafka client closed")
}

func (kp *KafkaPusher) Push(ctx context.Context, bs []byte) error {
	r := kp.kc.ProduceSync(ctx, &kgo.Record{
		Topic: kp.ktopic,
		Value: bs,
	})
	if err := r.FirstErr(); err != nil {
		return fmt.Errorf("failed to produce message to Kafka: %w", err)
	}
	return nil
}
