package cursor

const agentClientMessage = "agent.v1.AgentClientMessage"

// Only self-contained Agent messages are admitted. A descriptor's presence
// does not authorize blob references, cached context, credentials, or streams
// whose logical text crosses message boundaries.
var agentFields = map[string][]int{
	agentClientMessage:                            {1, 2, 4, 5, 7},
	"agent.v1.AgentRunRequest":                    {1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 22, 23, 24, 25, 26, 28, 31, 32, 33, 34, 36, 37},
	"agent.v1.ConversationStateStructure":         {4, 9, 10, 17, 18, 19, 22, 26, 27, 33, 34, 35, 36, 37, 38, 39, 42, 49, 50, 51},
	"agent.v1.ConversationAction":                 {1, 2, 3, 11},
	"agent.v1.UserMessageAction":                  {1, 2, 3, 4},
	"agent.v1.ResumeAction":                       {2},
	"agent.v1.CancelAction":                       {1},
	"agent.v1.UserMessage":                        {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 16, 17, 21, 24, 25, 26, 27, 28, 30, 31, 33, 34, 35, 36, 37, 38},
	"agent.v1.SelectedContext":                    {3, 4, 5, 6, 7, 10, 12, 16},
	"agent.v1.ExtraContextEntry":                  {1},
	"agent.v1.SelectedFile":                       {1, 2, 3},
	"agent.v1.SelectedCodeSelection":              {1, 2, 3, 4},
	"agent.v1.SelectedTerminal":                   {1, 2, 3},
	"agent.v1.SelectedTerminalSelection":          {1, 2, 3, 4},
	"agent.v1.SelectedCursorRule":                 {1},
	"agent.v1.SelectedCursorCommand":              {1, 2, 4, 5},
	"agent.v1.Range":                              {1, 2},
	"agent.v1.Position":                           {1, 2},
	"agent.v1.CursorRule":                         {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
	"agent.v1.CursorRuleType":                     {1, 2, 3, 4},
	"agent.v1.CursorRuleTypeGlobal":               {},
	"agent.v1.CursorRuleTypeFileGlobs":            {1},
	"agent.v1.CursorRuleTypeAgentFetched":         {1},
	"agent.v1.CursorRuleTypeManuallyAttached":     {},
	"agent.v1.RequestContext":                     {2, 4, 7, 8, 9, 16, 17, 19, 20, 21, 24, 25, 26, 27, 32, 33, 35, 36, 37, 39, 40, 41, 42, 43, 44, 45, 49, 50, 51, 52},
	"agent.v1.RequestContext.file_contentsEntry":  {1, 2},
	"agent.v1.RequestContextEnv":                  {1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 28},
	"agent.v1.ModelDetails":                       {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.ThinkingDetails":                    {},
	"agent.v1.RequestedModel":                     {1, 2, 3, 7},
	"agent.v1.RequestedModel.ModelParameterValue": {1, 2},
	"agent.v1.McpTools":                           {1},
	"agent.v1.McpToolDefinition":                  {1, 2, 3, 4, 5, 6, 7, 8, 9},
	"agent.v1.ExecClientMessage":                  {1, 2, 3, 4, 7, 11, 15, 29, 39, 45},
	"agent.v1.ExecClientControlMessage":           {1, 2, 3},
	"agent.v1.ExecClientStreamClose":              {1},
	"agent.v1.ExecClientHeartbeat":                {1},
	"agent.v1.ExecClientThrow":                    {1, 2, 3, 4},
	"agent.v1.ClientHeartbeat":                    {},
	"agent.v1.HookAdditionalContext":              {1, 2},
	"agent.v1.ShellResult":                        {1, 2, 3, 4, 5, 7, 102, 103, 104},
	"agent.v1.ShellSuccess":                       {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
	"agent.v1.ShellFailure":                       {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	"agent.v1.ShellTimeout":                       {1, 2, 3},
	"agent.v1.ShellRejected":                      {1, 2, 3, 4},
	"agent.v1.ShellSpawnError":                    {1, 2, 3},
	"agent.v1.ShellPermissionDenied":              {1, 2, 3, 4},
	"agent.v1.OutputLocation":                     {1, 2, 3},
	"agent.v1.ReadResult":                         {1, 2, 3, 4, 5, 6},
	"agent.v1.ReadSuccess":                        {1, 2, 3, 4, 6, 8, 9, 10},
	"agent.v1.ReadError":                          {1, 2},
	"agent.v1.ReadRejected":                       {1, 2},
	"agent.v1.ReadFileNotFound":                   {1},
	"agent.v1.ReadPermissionDenied":               {1},
	"agent.v1.ReadInvalidFile":                    {1, 2},
	"agent.v1.WriteResult":                        {1, 3, 4, 5, 6},
	"agent.v1.WriteSuccess":                       {1, 2, 3, 4},
	"agent.v1.WritePermissionDenied":              {1, 2, 3, 4, 5},
	"agent.v1.WriteNoSpace":                       {1},
	"agent.v1.WriteError":                         {1, 2},
	"agent.v1.WriteRejected":                      {1, 2},
	"agent.v1.DeleteResult":                       {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.DeleteSuccess":                      {1, 2, 3, 4},
	"agent.v1.DeleteFileNotFound":                 {1},
	"agent.v1.DeleteNotFile":                      {1, 2},
	"agent.v1.DeletePermissionDenied":             {1, 2, 3},
	"agent.v1.DeleteFileBusy":                     {1},
	"agent.v1.DeleteRejected":                     {1, 2},
	"agent.v1.DeleteError":                        {1, 2},
	"agent.v1.McpResult":                          {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.McpSuccess":                         {1, 2, 3, 4, 5},
	"agent.v1.McpToolResultContentItem":           {1},
	"agent.v1.McpTextContent":                     {1, 2},
	"agent.v1.McpError":                           {1, 2, 4, 5, 6, 7, 8},
	"agent.v1.McpRejected":                        {1, 2},
	"agent.v1.McpPermissionDenied":                {1, 2},
	"agent.v1.McpToolNotFound":                    {1, 2},
	"agent.v1.McpServerNotFound":                  {1, 2},
	"agent.v1.McpApproved":                        {},
	"agent.v1.SystemReminder":                     {1},
}

func agentContent(message, field string) bool {
	switch message {
	case "agent.v1.AgentRunRequest":
		return field == "custom_system_prompt"
	case "agent.v1.UserMessage":
		return field == "text" || field == "rich_text" || field == "subagent_system_reminder" || field == "forked_context"
	case "agent.v1.SelectedFile", "agent.v1.SelectedCodeSelection",
		"agent.v1.SelectedTerminal", "agent.v1.SelectedTerminalSelection",
		"agent.v1.SelectedCursorCommand":
		return field == "content"
	case "agent.v1.CursorRule":
		return field == "content" || field == "frontmatter"
	case "agent.v1.SelectedContext":
		return field == "extra_context"
	case "agent.v1.ExtraContextEntry":
		return field == "data"
	case "agent.v1.HookAdditionalContext":
		return field == "content"
	case "agent.v1.RequestContext":
		return field == "cloud_rule" || field == "user_intent_summary" || field == "hooks_additional_context" ||
			field == "conversation_notes_listing" || field == "shared_notes_listing"
	case "agent.v1.ShellSuccess", "agent.v1.ShellFailure":
		return field == "stdout" || field == "stderr" || field == "interleaved_output" || field == "output_head" || field == "output_tail"
	case "agent.v1.ReadSuccess":
		return field == "content"
	case "agent.v1.WriteSuccess":
		return field == "file_content_after_write"
	case "agent.v1.DeleteSuccess":
		return field == "prev_content"
	case "agent.v1.McpTextContent":
		return field == "text"
	case "agent.v1.SystemReminder":
		return field == "body"
	case "agent.v1.McpToolDefinition":
		return field == "description" || field == "input_schema_json" || field == "output_schema_json" ||
			field == "annotations_json" || field == "meta_json"
	case "agent.v1.ConversationStateStructure":
		return field == "durable_skill_blocks" || field == "project_coordinator_system_section"
	}
	return false
}

// Ordered MCP text items can form one logical output. Inspect their
// concatenation as well as individual fields/metadata, without rewriting them.
func (m *InferenceMessage) collectAgentMcpText(message *wireMessage, key *wireField) error {
	var targets []*wireField
	textSize := int64(2) // The quotes around the combined JSON string.
	for _, field := range message.fields {
		if field.def.Number != 1 {
			continue
		}
		part := field.child.field(1)
		if part == nil {
			continue
		}
		text := part.child.field(1)
		if text == nil {
			continue
		}
		targets = append(targets, text)
		textSize += jsonStringSize(text.payload) - 2
	}
	if len(targets) < 2 {
		return nil
	}
	label := []byte("text")
	if key != nil {
		label = key.payload
	}
	size := int64(3) + jsonStringSize(label) + textSize
	if len(m.slots) != 0 {
		size++
	}
	if m.jsonBytes+size > m.maxBytes {
		return ErrLimit
	}
	m.jsonBytes += size
	m.slots = append(m.slots, textSlot{name: string(label), targets: targets, key: key, content: true})
	return nil
}
