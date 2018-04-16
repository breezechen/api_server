// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"net/url"
	"runtime/debug"
	"strings"

	l4g "github.com/alecthomas/log4go"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/utils"
)

func (a *App) Config() *model.Config {
	if cfg := a.config.Load(); cfg != nil {
		return cfg.(*model.Config)
	}
	return &model.Config{}
}

func (a *App) UpdateConfig(f func(*model.Config)) {
	old := a.Config()
	updated := old.Clone()
	f(updated)
	a.config.Store(updated)
}

func (a *App) PersistConfig() {
	utils.SaveConfig(a.ConfigFileName(), a.Config())
}

func (a *App) LoadConfig(configFile string) *model.AppError {
	cfg, configPath, err := utils.LoadConfig(configFile)
	if err != nil {
		return err
	}

	a.configFile = configPath
	utils.ConfigureLog(&cfg.LogSettings)
	l4g.Info("Using config file at %s", configPath)

	a.config.Store(cfg)

	a.siteURL = strings.TrimRight(*cfg.ServiceSettings.SiteURL, "/")

	return nil
}

func (a *App) ReloadConfig() *model.AppError {
	debug.FreeOSMemory()
	if err := a.LoadConfig(a.configFile); err != nil {
		return err
	}
	return nil
}

func (a *App) ConfigFileName() string {
	return a.configFile
}

func (a *App) Desanitize(cfg *model.Config) {
	actual := a.Config()

	if *cfg.SqlSettings.DataSource == model.FAKE_SETTING {
		*cfg.SqlSettings.DataSource = *actual.SqlSettings.DataSource
	}
	if cfg.SqlSettings.AtRestEncryptKey == model.FAKE_SETTING {
		cfg.SqlSettings.AtRestEncryptKey = actual.SqlSettings.AtRestEncryptKey
	}

	for i := range cfg.SqlSettings.DataSourceReplicas {
		cfg.SqlSettings.DataSourceReplicas[i] = actual.SqlSettings.DataSourceReplicas[i]
	}

	for i := range cfg.SqlSettings.DataSourceSearchReplicas {
		cfg.SqlSettings.DataSourceSearchReplicas[i] = actual.SqlSettings.DataSourceSearchReplicas[i]
	}
}

func (a *App) GetCookieDomain() string {
	if *a.Config().ServiceSettings.AllowCookiesForSubdomains {
		if siteURL, err := url.Parse(*a.Config().ServiceSettings.SiteURL); err == nil {
			return siteURL.Hostname()
		}
	}
	return ""
}

func (a *App) GetSiteURL() string {
	return a.siteURL
}
