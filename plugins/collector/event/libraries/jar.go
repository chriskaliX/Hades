package libraries

import (
	"archive/zip"
	"bufio"
	"collector/cache/container"
	"collector/cache/process"
	"collector/utils"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/maps"
)

const jarMaxProcess = 10000

type Jar struct {
	JarName    string `mapstructure:"name"`
	Version    string `mapstructure:"version"`
	Path       string `mapstructure:"path"`
	regVersion *regexp.Regexp
}

func (Jar) DataType() int { return 3015 }

func (Jar) Name() string { return "jar" }

func (j *Jar) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	var pids []int
	pids, err = process.GetPids(jarMaxProcess)
	if err != nil {
		return
	}
	// go through the processes
	for _, pid := range pids {
		proc, err := process.GetProcessInfo(pid, false)
		if err != nil {
			continue
		}
		time.Sleep(50 * time.Millisecond)
		// extract java process
		if proc.Name != "java" {
			continue
		}
		fds, err := proc.Fds()
		if err != nil {
			continue
		}
		set := make(map[string]struct{})
		// fullup properties of pid
		var container_id, container_name string
		if proc.Pns != 0 {
			if containerInfo, ok := container.ContainerInfo(uint32(proc.Pns)); ok {
				container_id = containerInfo[container.ContainerId]
				container_name = containerInfo[container.ContainerName]
			}
		}
		rec := &protocol.Record{
			DataType: int32(j.DataType()),
			Data: &protocol.Payload{
				Fields: map[string]string{
					"pid":            strconv.Itoa(proc.PID),
					"pod_name":       proc.PodName,
					"cmdline":        proc.Argv,
					"container_id":   container_id,
					"container_name": container_name,
				},
			},
		}
		m := make(map[string]string, 3)
		// go through the file descriptions
		for _, fd := range fds {
			if filepath.Ext(fd) != ".jar" {
				continue
			}
			// set filter
			if _, ok := set[filepath.Base(fd)]; ok {
				continue
			}
			set[filepath.Base(fd)] = struct{}{}
			// name filter

			name, version := j.parseJarName(filepath.Base(fd))
			// dive into the jar, go through this, handle with the fatjar too
			if r, err := zip.OpenReader(filepath.Join("/proc", strconv.Itoa(pid), "root", fd)); err == nil {
				for _, f := range r.File {
					// Is this a fatjar, or this a normal jar file
					switch {
					case strings.HasSuffix(f.Name, ".jar"):
						j.JarName, j.Version = j.parseJarName(f.Name)
						j.Path = fd
						mapstructure.Decode(j, &m)
						maps.Copy(rec.Data.Fields, m)
						rec.Data.Fields["package_seq"] = hash
						time.Sleep(50 * time.Millisecond)
						s.SendRecord(rec)
					case version == "" && f.Name == "META-INF/MANIFEST.MF":
						// Version from main section
						if reader, err := f.Open(); err == nil {
							for sc := bufio.NewScanner(reader); sc.Scan(); {
								if strings.HasPrefix(sc.Text(), "Implementation-Version:") {
									version = strings.TrimSpace(sc.Text()[len("Implementation-Version:"):])
									break
								}
							}
							reader.Close()
						}
					}
				}
				r.Close()
				j.JarName = name
				j.Version = version
				j.Path = fd
				mapstructure.Decode(j, &m)
				maps.Copy(rec.Data.Fields, m)
				// cmdline may too long
				rec.Data.Fields["package_seq"] = hash
				time.Sleep(60 * time.Millisecond)
				s.SendRecord(rec)
			}
		}
	}
	return
}

func (j *Jar) parseJarName(jar string) (name, version string) {
	if j.regVersion == nil {
		j.regVersion = regexp.MustCompile(`-(\d+\.)+(\d+)\.jar`)
	}
	s := j.regVersion.FindString(jar)
	if s == "" {
		name = strings.TrimSuffix(jar, ".jar")
		return
	} else {
		version = strings.TrimSuffix(strings.TrimPrefix(s, "-"), ".jar")
		name = strings.TrimRight(jar, "-"+version+".jar")
		return
	}
}

func (j *Jar) reset() {
	j.JarName, j.Version, j.Path = "", "", ""
}

func init() { addEvent(&Jar{}) }
