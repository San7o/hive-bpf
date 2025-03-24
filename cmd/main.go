package main

import (
	"log"
	"syscall"
	"io/ioutil"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Target string `yaml:"target"`
}

func ParseYaml() (Config, error) {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return Config{}, errors.New("Error opening config file")
	}

	var config Config

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return Config{}, errors.New("Error parsing config file")
	}

	return config, nil
}

// Extract major and minor numbers from dev_t
func major(dev uint64) uint32 { return uint32((dev >> 8) & 0xfff) }
func minor(dev uint64) uint32 { return uint32((dev & 0xff)  | ((dev >> 12) & 0xfff00)) }

func GetInode(Target string) (uint64, uint32, uint32, error) {
	fd, err := syscall.Open(Target, syscall.O_RDONLY, 444)
	if err != nil {
		return 0, 0, 0, err
	}
	defer syscall.Close(fd)

	var stat syscall.Stat_t
	err = syscall.Fstat(fd, &stat)
	if err != nil {
		return 0, 0, 0, err
	}

	return stat.Ino, major(stat.Dev), minor(stat.Dev), nil
}

func main() {

	config, err := ParseYaml()
	if err != nil {
		log.Fatalf("Error ParseYaml: ", err)
	}
	log.Print("Targeting file: ", config.Target)
	
	kprobed_func := "inode_permission"
	
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock: %s", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %s", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(kprobed_func, objs.KprobeInodePermission, nil)
	if err != nil {
		log.Fatalf("Opening kprobe: %s", err)
	}
	defer kp.Close()

	ino, _, _, err := GetInode(config.Target)
	if err != nil {
		log.Fatalf("GetInode: %s", err)
	}

	log.Print("Opened file with inode number ", ino)

	ino2, _, _, err := GetInode("LICENSE")
	if err != nil {
		log.Fatalf("GetInode again: %s", err)
	}
	
	// TODO: Add more inodes for testing
	var key0 uint32 = 0
	var key1 uint32 = 1
	err = objs.TracedInodes.Update(key0, ino, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Updating map: %s", err)
	}
	err = objs.TracedInodes.Update(key1, ino2, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Updating map: %s", err)
	}

	for {
	}
}
