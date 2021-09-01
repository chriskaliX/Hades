package network

import (
	"hids-agent/global"
	"reflect"
	"sync"

	"github.com/Shopify/sarama"
)

var (
	KafkaSingleton *Kafka
	KafkaContext   *Context
	KafkaLogPool   *sync.Pool
	KafkaChannel   chan *KafkaLog
	once           sync.Once
)

func GetKafkaSingleton() *Kafka {
	once.Do(func() {
		KafkaSingleton = &Kafka{}
	})
	return KafkaSingleton
}

func init() {
	KafkaLogPool = &sync.Pool{
		New: func() interface{} {
			kafka := &KafkaLog{}
			kafka.IP = "192.168.0.1"
			kafka.Hostname = global.Hostname
			return kafka
		},
	}
	KafkaChannel = make(chan *KafkaLog, 5000)
}

type KafkaLog struct {
	IP       string
	Hostname string
	Pstree   string

	Process
}

type Process struct {
	PID         int      `json:"pid"`
	PPID        int      `json:"ppid"`
	Name        string   `json:"name"`
	Cmdline     string   `json:"cmdline"`
	Exe         string   `json:"exe"`
	Sha256      string   `json:"sha256"`
	UID         string   `json:"uid"`
	Username    string   `json:"username"`
	EUID        string   `json:"euid"`
	Eusername   string   `json:"eusername"`
	Cwd         string   `json:"cwd"`
	Session     int      `json:"session"`
	TTY         int      `json:"tty"`
	StartTime   uint64   `json:"start_time"`
	RemoteAddrs []string `json:"RemoteAddrs"`
	PsTree      string   `json:"PsTree"`
}

// Kafka, 实现 IRetry 接口
type Kafka struct {
	Producer *sarama.SyncProducer
	Config   *sarama.Config
	Address  *[]string
	Topic    string
}

func (k *Kafka) Init() error {
	if k.Config == nil {
		k.LoadConfig()
	}
	return nil
}

func (k *Kafka) Connect() error {
	producer, err := sarama.NewSyncProducer([]string{"localhost:9092"}, k.Config)
	if err != nil {
		return err
	}

	k.Producer = &producer
	return nil
}

func (k *Kafka) GetMaxRetry() uint {
	return 5
}

func (k *Kafka) String() string {
	return reflect.TypeOf(k).String()
}

func (k *Kafka) GetHashMod() uint {
	return 1
}

func (k *Kafka) Close() {
	if k != nil {
		(*k.Producer).Close()
	}
}

func (this *Kafka) LoadConfig() error {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.RequiredAcks = sarama.WaitForAll
	kafkaConfig.Producer.Partitioner = sarama.NewRandomPartitioner
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true
	kafkaConfig.Version = sarama.V0_11_0_2

	this.Config = kafkaConfig
	return nil
}

func (this *Kafka) Product() {

}

func KafkaInit() error {
	KafkaSingleton.LoadConfig()
	KafkaContext = &Context{}
	err := KafkaContext.IRetry(KafkaSingleton)
	if err != nil {
		return err
	}
	return nil
}
