package go_nessus

type CreateScanResponse struct {
	Scan struct {
		ContainerID          int         `json:"container_id"`
		CreationDate         int         `json:"creation_date"`
		CustomTargets        string      `json:"custom_targets"`
		DashboardFile        interface{} `json:"dashboard_file"`
		DefaultPermisssions  int         `json:"default_permisssions"`
		Description          string      `json:"description"`
		Emails               string      `json:"emails"`
		Enabled              bool        `json:"enabled"`
		ID                   int         `json:"id"`
		LastModificationDate int         `json:"last_modification_date"`
		Name                 string      `json:"name"`
		NotificationFilters  interface{} `json:"notification_filters"`
		Owner                string      `json:"owner"`
		OwnerID              int         `json:"owner_id"`
		PolicyID             int         `json:"policy_id"`
		Rrules               interface{} `json:"rrules"`
		ScanTimeWindow       interface{} `json:"scan_time_window"`
		ScannerID            int         `json:"scanner_id"`
		Shared               int         `json:"shared"`
		Sms                  interface{} `json:"sms"`
		Starttime            interface{} `json:"starttime"`
		TagID                int         `json:"tag_id"`
		Timezone             string      `json:"timezone"`
		Type                 string      `json:"type"`
		UseDashboard         bool        `json:"use_dashboard"`
		UserPermissions      int         `json:"user_permissions"`
		UUID                 string      `json:"uuid"`
	} `json:"scan"`
}

type CreateScanSettings struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Folder_id    string `json:"folder_id"`
	Scanner_id   string `json:"scanner_id"`
	Policy_id    string `json:"policy_id"`
	Text_targets string `json:"text_targets"`
	File_targets string `json:"file_targets"`
	Launch       string `json:"launch"`
	Enabled      bool   `json:"enabled"`
	Launch_now   bool   `json:"launch_now"`
	Emails       string `json:"emails"`
}

type CreateScan struct {
	Uuid     string             `json:"uuid"`
	Settings CreateScanSettings `json:"settings"`
}
