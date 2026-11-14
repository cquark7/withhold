package cursor

// Ordinary editor startup/configuration calls use typed inspection, not a
// host-wide metadata exemption. Strings are scanned and immutable; unknown
// fields and gateway credentials remain unsupported.
var controlRoutes = map[string]string{
	"/aiserver.v1.DashboardService/GetTeamAdminSettingsOrEmptyIfNotInTeam":   "aiserver.v1.GetTeamAdminSettingsRequest",
	"/aiserver.v1.DashboardService/GetTeamReposOrEmptyIfNotInTeam":           "aiserver.v1.GetTeamReposRequest",
	"/aiserver.v1.DashboardService/GetEffectiveUserPlugins":                  "aiserver.v1.GetEffectiveUserPluginsRequest",
	"/aiserver.v1.MCPRegistryService/GetKnownServers":                        "aiserver.v1.GetKnownServersRequest",
	"/aiserver.v1.DashboardService/GetManagedSkills":                         "aiserver.v1.GetManagedSkillsRequest",
	"/aiserver.v1.AnalyticsService/BootstrapStatsig":                         "aiserver.v1.BootstrapStatsigRequest",
	"/aiserver.v1.DashboardService/GetEffectiveUserAgentStoreSkillsSettings": "aiserver.v1.GetEffectiveUserAgentStoreSkillsSettingsRequest",
	"/aiserver.v1.DashboardService/GetMe":                                    "aiserver.v1.GetMeRequest",
	"/aiserver.v1.DashboardService/ListMarketplaces":                         "aiserver.v1.ListMarketplacesRequest",
	"/aiserver.v1.ServerConfigService/GetServerConfig":                       "aiserver.v1.GetServerConfigRequest",
	"/aiserver.v1.DashboardService/GetScmConnectionStatus":                   "aiserver.v1.GetScmConnectionStatusRequest",
	"/aiserver.v1.AiService/GetRealtimeVoice":                                "aiserver.v1.GetRealtimeVoiceRequest",
	"/aiserver.v1.AiService/UpdateVscodeProfile":                             "aiserver.v1.UpdateVscodeProfileRequest",
	"/aiserver.v1.AiService/AvailableModels":                                 "aiserver.v1.AvailableModelsRequest",
}

var controlFields = map[string][]int{
	"aiserver.v1.GetTeamAdminSettingsRequest":                     {1, 2},
	"aiserver.v1.GetTeamReposRequest":                             {1},
	"aiserver.v1.GetEffectiveUserPluginsRequest":                  {1, 2, 4},
	"aiserver.v1.GetKnownServersRequest":                          {},
	"aiserver.v1.GetManagedSkillsRequest":                         {1, 2},
	"aiserver.v1.BootstrapStatsigRequest":                         {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	"aiserver.v1.BootstrapStatsigRequest.NameFilter":              {1, 2, 3},
	"aiserver.v1.GetEffectiveUserAgentStoreSkillsSettingsRequest": {},
	"aiserver.v1.GetMeRequest":                                    {1, 2, 3},
	"aiserver.v1.ListMarketplacesRequest":                         {},
	"aiserver.v1.GetServerConfigRequest":                          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	"aiserver.v1.GetScmConnectionStatusRequest":                   {1, 2, 3},
	"aiserver.v1.GetRealtimeVoiceRequest":                         {},
	"aiserver.v1.UpdateVscodeProfileRequest":                      {1, 2, 3},
	"aiserver.v1.AvailableModelsRequest":                          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 18, 19},
	"aiserver.v1.CloudAgentRequestScope":                          {1, 2},
	"aiserver.v1.CloudAgentPersonalScope":                         {},
	"aiserver.v1.DevEnvironment":                                  {1, 2},
	"aiserver.v1.RemoteAuthority":                                 {1},
	"aiserver.v1.ScmConnectAdContext":                             {1, 2, 3},
	"aiserver.v1.VscodeCPUProperties":                             {1, 2},
	"aiserver.v1.VscodeOSProperties":                              {1, 2, 3, 4, 5},
	"aiserver.v1.VscodeOSStatistics":                              {1, 2, 3},
}
