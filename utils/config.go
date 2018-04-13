// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"	
	"strings"

	l4g "github.com/alecthomas/log4go"
	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"net/http"

	"github.com/WTHealth/server/model"
)

const (
	LOG_ROTATE_SIZE = 10000
	LOG_FILENAME    = "mattermost.log"
)

var originalDisableDebugLvl l4g.Level = l4g.DEBUG

// FindConfigFile attempts to find an existing configuration file. fileName can be an absolute or
// relative path or name such as "/opt/mattermost/config.json" or simply "config.json". An empty
// string is returned if no configuration is found.
func FindConfigFile(fileName string) (path string) {
	if filepath.IsAbs(fileName) {
		if _, err := os.Stat(fileName); err == nil {
			return fileName
		}
	} else {
		for _, dir := range []string{"./config", "../config", "../../config", "."} {
			path, _ := filepath.Abs(filepath.Join(dir, fileName))
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}

// FindDir looks for the given directory in nearby ancestors, falling back to `./` if not found.
func FindDir(dir string) (string, bool) {
	for _, parent := range []string{".", "..", "../.."} {
		foundDir, err := filepath.Abs(filepath.Join(parent, dir))
		if err != nil {
			continue
		} else if _, err := os.Stat(foundDir); err == nil {
			return foundDir, true
		}
	}
	return "./", false
}

func DisableDebugLogForTest() {
	if l4g.Global["stdout"] != nil {
		originalDisableDebugLvl = l4g.Global["stdout"].Level
		l4g.Global["stdout"].Level = l4g.ERROR
	}
}

func EnableDebugLogForTest() {
	if l4g.Global["stdout"] != nil {
		l4g.Global["stdout"].Level = originalDisableDebugLvl
	}
}

func ConfigureCmdLineLog() {
	ls := model.LogSettings{}
	ls.EnableConsole = true
	ls.ConsoleLevel = "WARN"
	ConfigureLog(&ls)
}

// TODO: this code initializes console and file logging. It will eventually be replaced by JSON logging in logger/logger.go
// See PLT-3893 for more information
func ConfigureLog(s *model.LogSettings) {

	l4g.Close()

	if s.EnableConsole {
		level := l4g.DEBUG
		if s.ConsoleLevel == "INFO" {
			level = l4g.INFO
		} else if s.ConsoleLevel == "WARN" {
			level = l4g.WARNING
		} else if s.ConsoleLevel == "ERROR" {
			level = l4g.ERROR
		}

		lw := l4g.NewConsoleLogWriter()
		lw.SetFormat("[%D %T] [%L] %M")
		l4g.AddFilter("stdout", level, lw)
	}

	if s.EnableFile {

		var fileFormat = s.FileFormat

		if fileFormat == "" {
			fileFormat = "[%D %T] [%L] %M"
		}

		level := l4g.DEBUG
		if s.FileLevel == "INFO" {
			level = l4g.INFO
		} else if s.FileLevel == "WARN" {
			level = l4g.WARNING
		} else if s.FileLevel == "ERROR" {
			level = l4g.ERROR
		}

		flw := l4g.NewFileLogWriter(GetLogFileLocation(s.FileLocation), false)
		flw.SetFormat(fileFormat)
		flw.SetRotate(true)
		flw.SetRotateLines(LOG_ROTATE_SIZE)
		l4g.AddFilter("file", level, flw)
	}
}

func GetLogFileLocation(fileLocation string) string {
	if fileLocation == "" {
		fileLocation, _ = FindDir("logs")
	}

	return filepath.Join(fileLocation, LOG_FILENAME)
}

func SaveConfig(fileName string, config *model.Config) *model.AppError {
	b, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return model.NewAppError("SaveConfig", "utils.config.save_config.saving.app_error",
			map[string]interface{}{"Filename": fileName}, err.Error(), http.StatusBadRequest)
	}

	err = ioutil.WriteFile(fileName, b, 0644)
	if err != nil {
		return model.NewAppError("SaveConfig", "utils.config.save_config.saving.app_error",
			map[string]interface{}{"Filename": fileName}, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

type ConfigWatcher struct {
	watcher *fsnotify.Watcher
	close   chan struct{}
	closed  chan struct{}
}

func NewConfigWatcher(cfgFileName string, f func()) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create config watcher for file: "+cfgFileName)
	}

	configFile := filepath.Clean(cfgFileName)
	configDir, _ := filepath.Split(configFile)
	watcher.Add(configDir)

	ret := &ConfigWatcher{
		watcher: watcher,
		close:   make(chan struct{}),
		closed:  make(chan struct{}),
	}

	go func() {
		defer close(ret.closed)
		defer watcher.Close()

		for {
			select {
			case event := <-watcher.Events:
				// we only care about the config file
				if filepath.Clean(event.Name) == configFile {
					if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
						l4g.Info(fmt.Sprintf("Config file watcher detected a change reloading %v", cfgFileName))

						if _, configReadErr := ReadConfigFile(cfgFileName, true); configReadErr == nil {
							f()
						} else {
							l4g.Error(fmt.Sprintf("Failed to read while watching config file at %v with err=%v", cfgFileName, configReadErr.Error()))
						}
					}
				}
			case err := <-watcher.Errors:
				l4g.Error(fmt.Sprintf("Failed while watching config file at %v with err=%v", cfgFileName, err.Error()))
			case <-ret.close:
				return
			}
		}
	}()

	return ret, nil
}

func (w *ConfigWatcher) Close() {
	close(w.close)
	<-w.closed
}

// ReadConfig reads and parses the given configuration.
func ReadConfig(r io.Reader, allowEnvironmentOverrides bool) (*model.Config, error) {
	v := newViper(allowEnvironmentOverrides)

	if err := v.ReadConfig(r); err != nil {
		return nil, err
	}

	var config model.Config
	unmarshalErr := v.Unmarshal(&config)

	return &config, unmarshalErr
}

func newViper(allowEnvironmentOverrides bool) *viper.Viper {
	v := viper.New()

	v.SetConfigType("json")

	if allowEnvironmentOverrides {
		v.SetEnvPrefix("mm")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()
	}

	// Set zeroed defaults for all the config settings so that Viper knows what environment variables
	// it needs to be looking for. The correct defaults will later be applied using Config.SetDefaults.
	defaults := flattenStructToMap(structToMap(reflect.TypeOf(model.Config{})))

	for key, value := range defaults {
		v.SetDefault(key, value)
	}

	return v
}

// Converts a struct type into a nested map with keys matching the struct's fields and values
// matching the zeroed value of the corresponding field.
func structToMap(t reflect.Type) map[string]interface{} {
	if t.Kind() != reflect.Struct {
		// Should never hit this, but this will prevent a panic if that does happen somehow
		return nil
	}

	out := make(map[string]interface{})

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		var value interface{}

		switch field.Type.Kind() {
		case reflect.Struct:
			value = structToMap(field.Type)
		case reflect.Ptr:
			value = nil
		default:
			value = reflect.Zero(field.Type).Interface()
		}

		out[field.Name] = value
	}

	return out
}

// Flattens a nested map so that the result is a single map with keys corresponding to the
// path through the original map. For example,
// {
//     "a": {
//         "b": 1
//     },
//     "c": "sea"
// }
// would flatten to
// {
//     "a.b": 1,
//     "c": "sea"
// }
func flattenStructToMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})

	for key, value := range in {
		if valueAsMap, ok := value.(map[string]interface{}); ok {
			sub := flattenStructToMap(valueAsMap)

			for subKey, subValue := range sub {
				out[key+"."+subKey] = subValue
			}
		} else {
			out[key] = value
		}
	}

	return out
}

// ReadConfigFile reads and parses the configuration at the given file path.
func ReadConfigFile(path string, allowEnvironmentOverrides bool) (*model.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadConfig(f, allowEnvironmentOverrides)
}

// EnsureConfigFile will attempt to locate a config file with the given name. If it does not exist,
// it will attempt to locate a default config file, and copy it to a file named fileName in the same
// directory. In either case, the config file path is returned.
func EnsureConfigFile(fileName string) (string, error) {
	if configFile := FindConfigFile(fileName); configFile != "" {
		return configFile, nil
	}
	if defaultPath := FindConfigFile("default.json"); defaultPath != "" {
		destPath := filepath.Join(filepath.Dir(defaultPath), fileName)
		src, err := os.Open(defaultPath)
		if err != nil {
			return "", err
		}
		defer src.Close()
		dest, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return "", err
		}
		defer dest.Close()
		if _, err := io.Copy(dest, src); err == nil {
			return destPath, nil
		}
	}
	return "", fmt.Errorf("no config file found")
}

// LoadConfig will try to search around for the corresponding config file.  It will search
// /tmp/fileName then attempt ./config/fileName, then ../config/fileName and last it will look at
// fileName.
func LoadConfig(fileName string) (config *model.Config, configPath string, appErr *model.AppError) {
	if fileName != filepath.Base(fileName) {
		configPath = fileName
	} else {
		if path, err := EnsureConfigFile(fileName); err != nil {
			appErr = model.NewAppError("LoadConfig", "utils.config.load_config.opening.panic", map[string]interface{}{"Filename": fileName, "Error": err.Error()}, "", 0)
			return
		} else {
			configPath = path
		}
	}

	config, err := ReadConfigFile(configPath, true)
	if err != nil {
		appErr = model.NewAppError("LoadConfig", "utils.config.load_config.decoding.panic", map[string]interface{}{"Filename": fileName, "Error": err.Error()}, "", 0)
		return
	}

	needSave := len(config.SqlSettings.AtRestEncryptKey) == 0

	config.SetDefaults()

	if err := config.IsValid(); err != nil {
		return nil, "", err
	}

	if needSave {
		if err := SaveConfig(configPath, config); err != nil {
			l4g.Warn(err.Error())
		}
	}

	return config, configPath, nil
}
