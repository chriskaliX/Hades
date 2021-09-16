package network

import (
	"reflect"

	"github.com/Shopify/sarama"
)

var (
	KafkaSingleton *Kafka
	KafkaContext   *Context
	KafkaChannel   = make(chan string, 1000)
)

// Kafka, 实现 IRetry 接口
type Kafka struct {
	Producer sarama.SyncProducer
	Config   sarama.Config
	Address  []string
	Topic    string
}

func (k *Kafka) Init() error {
	if &k.Config == nil {
		kafkaConfig := sarama.NewConfig()
		kafkaConfig.Producer.RequiredAcks = sarama.WaitForAll
		kafkaConfig.Producer.Partitioner = sarama.NewRandomPartitioner
		kafkaConfig.Producer.Return.Successes = true
		kafkaConfig.Producer.Return.Errors = true
		kafkaConfig.Version = sarama.V0_11_0_2
		k.Config = *kafkaConfig
	}
	return nil
}

func (k *Kafka) Connect() (err error) {
	k.Producer, err = sarama.NewSyncProducer([]string{"localhost:9092"}, &k.Config)
	return
}

func (k *Kafka) GetMaxRetry() uint {
	return 3
}

func (k *Kafka) String() string {
	return reflect.TypeOf(k).String()
}

func (k *Kafka) GetHashMod() uint {
	return 1
}

func (k *Kafka) Close() {
	if k != nil {
		k.Producer.Close()
	}
}

func (this *Kafka) Send(message string) (err error) {
	msg := &sarama.ProducerMessage{
		Topic: this.Topic,
		Value: sarama.StringEncoder(message),
	}
	_, _, err = this.Producer.SendMessage(msg)
	return
}

func KafkaInit() (err error) {
	KafkaContext = &Context{}
	err = KafkaContext.IRetry(KafkaSingleton)
	return
}
