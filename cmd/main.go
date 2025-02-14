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

func GetInode(Target string) (uint64, error) {
	fd, err := syscall.Open(Target, syscall.O_RDONLY, 444)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var stat syscall.Stat_t
	err = syscall.Fstat(fd, &stat)
	if err != nil {
		return 0, err
	}

	return stat.Ino, nil
}

func main() {

	config, err := ParseYaml()
	if err != nil {
		log.Fatalf("Error ParseYaml: ", err)
	}
	
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

	ino, err := GetInode(config.Target)
	if err != nil {
		log.Fatalf("GetInode: %s", err)
	}

	log.Print("Opened file with inode number ", ino)

	var key uint32 = 0
	err = objs.TracedInodes.Update(key, ino, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Updating map: %s", err)
	}

	for {
	}
}
