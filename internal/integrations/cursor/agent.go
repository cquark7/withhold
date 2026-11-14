package cursor

const agentClientMessage = "agent.v1.AgentClientMessage"

// Only reviewed Agent fields are admitted. Blob references additionally need
// a complete typed graph locally available in this stream. A descriptor's
// presence does not authorize server caches, credentials, or output streams.
var agentFields = map[string][]int{
	agentClientMessage:                                                {1, 2, 4, 5, 7, 8},
	"agent.v1.AgentRunRequest":                                        {1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26, 28, 31, 32, 33, 34, 36, 37},
	"agent.v1.ConversationStateStructure":                             {3, 4, 6, 7, 8, 9, 10, 17, 18, 19, 22, 26, 27, 33, 34, 35, 36, 37, 38, 39, 42, 49, 50, 51},
	"agent.v1.ConversationAction":                                     {1, 2, 3, 11, 17},
	"agent.v1.UserMessageAction":                                      {1, 2, 3, 4},
	"agent.v1.ResumeAction":                                           {2},
	"agent.v1.CancelAction":                                           {1},
	"agent.v1.UserMessage":                                            {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19, 21, 24, 25, 26, 27, 28, 30, 31, 33, 34, 35, 36, 37, 38},
	"agent.v1.SelectedContext":                                        {3, 4, 5, 6, 7, 10, 12, 16},
	"agent.v1.ExtraContextEntry":                                      {1, 2},
	"agent.v1.SelectedFile":                                           {1, 2, 3},
	"agent.v1.SelectedCodeSelection":                                  {1, 2, 3, 4},
	"agent.v1.SelectedTerminal":                                       {1, 2, 3},
	"agent.v1.SelectedTerminalSelection":                              {1, 2, 3, 4},
	"agent.v1.SelectedCursorRule":                                     {1},
	"agent.v1.SelectedCursorCommand":                                  {1, 2, 4, 5},
	"agent.v1.Range":                                                  {1, 2},
	"agent.v1.Position":                                               {1, 2},
	"agent.v1.CursorRule":                                             {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
	"agent.v1.CursorRuleType":                                         {1, 2, 3, 4},
	"agent.v1.CursorRuleTypeGlobal":                                   {},
	"agent.v1.CursorRuleTypeFileGlobs":                                {1},
	"agent.v1.CursorRuleTypeAgentFetched":                             {1},
	"agent.v1.CursorRuleTypeManuallyAttached":                         {},
	"agent.v1.RequestContext":                                         {2, 4, 6, 7, 8, 9, 11, 13, 14, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 32, 33, 35, 36, 37, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52},
	"agent.v1.RequestContext.file_contentsEntry":                      {1, 2},
	"agent.v1.RequestContextEnv":                                      {1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 28},
	"agent.v1.ModelDetails":                                           {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.ThinkingDetails":                                        {},
	"agent.v1.RequestedModel":                                         {1, 2, 3, 7},
	"agent.v1.RequestedModel.ModelParameterValue":                     {1, 2},
	"agent.v1.McpTools":                                               {1},
	"agent.v1.McpToolDefinition":                                      {1, 2, 3, 4, 5, 6, 7, 8, 9},
	"agent.v1.ExecClientMessage":                                      {1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 15, 29, 39, 45, 55},
	"agent.v1.ExecClientControlMessage":                               {1, 2, 3},
	"agent.v1.ExecClientStreamClose":                                  {1},
	"agent.v1.ExecClientHeartbeat":                                    {1},
	"agent.v1.ExecClientThrow":                                        {1, 2, 3, 4},
	"agent.v1.ClientHeartbeat":                                        {},
	"agent.v1.HookAdditionalContext":                                  {1, 2},
	"agent.v1.ShellResult":                                            {1, 2, 3, 4, 5, 7, 102, 103, 104},
	"agent.v1.ShellSuccess":                                           {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
	"agent.v1.ShellFailure":                                           {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	"agent.v1.ShellTimeout":                                           {1, 2, 3},
	"agent.v1.ShellRejected":                                          {1, 2, 3, 4},
	"agent.v1.ShellSpawnError":                                        {1, 2, 3},
	"agent.v1.ShellPermissionDenied":                                  {1, 2, 3, 4},
	"agent.v1.OutputLocation":                                         {1, 2, 3},
	"agent.v1.ReadResult":                                             {1, 2, 3, 4, 5, 6},
	"agent.v1.ReadSuccess":                                            {1, 2, 3, 4, 6, 8, 9, 10},
	"agent.v1.ReadError":                                              {1, 2},
	"agent.v1.ReadRejected":                                           {1, 2},
	"agent.v1.ReadFileNotFound":                                       {1},
	"agent.v1.ReadPermissionDenied":                                   {1},
	"agent.v1.ReadInvalidFile":                                        {1, 2},
	"agent.v1.WriteResult":                                            {1, 3, 4, 5, 6},
	"agent.v1.WriteSuccess":                                           {1, 2, 3, 4},
	"agent.v1.WritePermissionDenied":                                  {1, 2, 3, 4, 5},
	"agent.v1.WriteNoSpace":                                           {1},
	"agent.v1.WriteError":                                             {1, 2},
	"agent.v1.WriteRejected":                                          {1, 2},
	"agent.v1.DeleteResult":                                           {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.DeleteSuccess":                                          {1, 2, 3, 4},
	"agent.v1.DeleteFileNotFound":                                     {1},
	"agent.v1.DeleteNotFile":                                          {1, 2},
	"agent.v1.DeletePermissionDenied":                                 {1, 2, 3},
	"agent.v1.DeleteFileBusy":                                         {1},
	"agent.v1.DeleteRejected":                                         {1, 2},
	"agent.v1.DeleteError":                                            {1, 2},
	"agent.v1.McpResult":                                              {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.McpSuccess":                                             {1, 2, 3, 4, 5},
	"agent.v1.McpToolResultContentItem":                               {1},
	"agent.v1.McpTextContent":                                         {1, 2},
	"agent.v1.McpError":                                               {1, 2, 4, 5, 6, 7, 8},
	"agent.v1.McpRejected":                                            {1, 2},
	"agent.v1.McpPermissionDenied":                                    {1, 2},
	"agent.v1.McpToolNotFound":                                        {1, 2},
	"agent.v1.McpServerNotFound":                                      {1, 2},
	"agent.v1.McpApproved":                                            {},
	"agent.v1.SystemReminder":                                         {1},
	"agent.v1.PreFetchedBlob":                                         {1, 2},
	"agent.v1.PrewarmRequest":                                         {1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 26, 28, 29, 30},
	"agent.v1.ConversationTurnStructure":                              {1, 2},
	"agent.v1.AgentConversationTurnStructure":                         {1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 15, 16},
	"agent.v1.ShellConversationTurnStructure":                         {1, 2},
	"agent.v1.ConversationStep":                                       {1, 2, 3},
	"agent.v1.AssistantMessage":                                       {1, 2, 3},
	"agent.v1.ThinkingMessage":                                        {1, 2, 3, 4},
	"agent.v1.TodoItem":                                               {1, 2, 3, 4, 5, 6},
	"agent.v1.ConversationSummary":                                    {1},
	"agent.v1.ConversationPlan":                                       {1},
	"agent.v1.ShellCommand":                                           {1},
	"agent.v1.ShellOutput":                                            {1, 2, 3},
	"agent.v1.RequestContextResult":                                   {1, 2, 3},
	"agent.v1.RequestContextSuccess":                                  {1, 2},
	"agent.v1.RequestContextError":                                    {1},
	"agent.v1.RequestContextRejected":                                 {1},
	"agent.v1.GitRepoInfo":                                            {1, 2, 3, 4, 5, 6},
	"agent.v1.RepositoryIndexingInfo":                                 {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	"agent.v1.McpInstructions":                                        {1, 2, 3},
	"agent.v1.AgentSkill":                                             {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	"agent.v1.SkillOptions":                                           {1},
	"agent.v1.SkillDescriptor":                                        {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.CustomSubagent":                                         {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
	"agent.v1.HooksConfigInfo":                                        {1},
	"agent.v1.PermissionsAutoRunInstructions":                         {1, 2},
	"agent.v1.LsDirectoryTreeNode":                                    {1, 2, 3, 4, 5, 6},
	"agent.v1.LsDirectoryTreeNode.full_subtree_extension_countsEntry": {1, 2},
	"agent.v1.LsDirectoryTreeNode.File":                               {1, 2},
	"agent.v1.TerminalMetadata":                                       {1, 2, 3, 4},
	"agent.v1.TerminalMetadata.Command":                               {1, 2, 3, 4},
	"agent.v1.GrepResult":                                             {1, 2},
	"agent.v1.GrepSuccess":                                            {1, 2, 3, 4, 5},
	"agent.v1.GrepSuccess.workspace_resultsEntry":                     {1, 2},
	"agent.v1.GrepUnionResult":                                        {1, 2, 3},
	"agent.v1.GrepContentResult":                                      {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.GrepFileMatch":                                          {1, 2},
	"agent.v1.GrepContentMatch":                                       {1, 2, 3, 4},
	"agent.v1.GrepFilesResult":                                        {1, 2, 3, 4, 5, 6},
	"agent.v1.GrepCountResult":                                        {1, 2, 3, 4, 5, 6, 7},
	"agent.v1.GrepFileCount":                                          {1, 2},
	"agent.v1.GrepError":                                              {1},
	"agent.v1.LsResult":                                               {1, 2, 3, 4},
	"agent.v1.LsSuccess":                                              {1},
	"agent.v1.LsError":                                                {1, 2},
	"agent.v1.LsRejected":                                             {1, 2},
	"agent.v1.LsTimeout":                                              {1},
	"agent.v1.DiagnosticsResult":                                      {1, 2, 3, 4, 5},
	"agent.v1.DiagnosticsSuccess":                                     {1, 2, 3},
	"agent.v1.Diagnostic":                                             {1, 2, 3, 4, 5, 6},
	"agent.v1.DiagnosticsError":                                       {1, 2},
	"agent.v1.DiagnosticsRejected":                                    {1, 2},
	"agent.v1.DiagnosticsFileNotFound":                                {1},
	"agent.v1.DiagnosticsPermissionDenied":                            {1},
	"agent.v1.ToolCall":                                               {1, 3, 4, 5, 8, 9, 10, 12, 13, 14, 15, 54, 57, 59, 60},
	"agent.v1.ShellToolCall":                                          {1, 2, 3},
	"agent.v1.ShellArgs":                                              {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25},
	"agent.v1.ShellCommandParsingResult":                              {1, 2, 3, 4, 5, 6},
	"agent.v1.ShellCommandParsingResult.ExecutableCommand":            {1, 2, 3},
	"agent.v1.ShellCommandParsingResult.ExecutableCommandArg":         {1, 2},
	"agent.v1.ShellCommandParsingResult.Redirect":                     {1, 2, 3, 4},
	"agent.v1.CommandClassifierResult":                                {1, 2, 3},
	"agent.v1.CommandClassifierResult.ClassifiedCommand":              {1, 2, 3, 4},
	"agent.v1.ShellOutputNotificationConfig":                          {1, 2, 3, 4},
	"agent.v1.ShellHookApprovalRequirement":                           {1, 2},
	"agent.v1.SmartModeApproval":                                      {1, 2},
	"agent.v1.SandboxPolicy":                                          {1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	"agent.v1.NetworkPolicy":                                          {1, 2, 3, 4, 5},
	"agent.v1.NetworkPolicyLoggingConfig":                             {1, 2},
	"agent.v1.ReadToolCall":                                           {1, 2},
	"agent.v1.ReadToolArgs":                                           {1, 2, 3, 5},
	"agent.v1.ReadToolResult":                                         {1, 2},
	"agent.v1.ReadToolSuccess":                                        {1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 13},
	"agent.v1.ReadToolError":                                          {1},
	"agent.v1.ReadRange":                                              {1, 2},
	"agent.v1.EditToolCall":                                           {1, 2},
	"agent.v1.EditArgs":                                               {1, 6},
	"agent.v1.EditResult":                                             {1, 2, 3, 4, 6, 7},
	"agent.v1.EditSuccess":                                            {1, 3, 4, 5, 6, 7, 8},
	"agent.v1.EditError":                                              {1, 2, 5},
	"agent.v1.EditFileNotFound":                                       {1},
	"agent.v1.EditReadPermissionDenied":                               {1},
	"agent.v1.EditWritePermissionDenied":                              {1, 2, 3},
	"agent.v1.EditRejected":                                           {1, 2},
	"agent.v1.DeleteToolCall":                                         {1, 2},
	"agent.v1.DeleteArgs":                                             {1, 2},
	"agent.v1.GlobToolCall":                                           {1, 2},
	"agent.v1.GlobToolArgs":                                           {1, 2},
	"agent.v1.GlobToolResult":                                         {1, 2},
	"agent.v1.GlobToolSuccess":                                        {1, 2, 3, 4, 5, 6},
	"agent.v1.GlobToolError":                                          {1},
	"agent.v1.GrepToolCall":                                           {1, 2},
	"agent.v1.GrepArgs":                                               {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	"agent.v1.LsToolCall":                                             {1, 2},
	"agent.v1.LsArgs":                                                 {1, 2, 3, 4, 5},
	"agent.v1.McpToolCall":                                            {1, 2, 3},
	"agent.v1.McpArgs":                                                {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	"agent.v1.McpArgs.argsEntry":                                      {1, 2},
	"agent.v1.McpToolResult":                                          {1, 2, 3, 4},
	"agent.v1.McpToolError":                                           {1, 2, 3},
	"agent.v1.McpSymbolicPathArgument":                                {1, 2, 3},
	"agent.v1.UpdateTodosToolCall":                                    {1, 2},
	"agent.v1.UpdateTodosArgs":                                        {1, 2},
	"agent.v1.UpdateTodosResult":                                      {1, 2},
	"agent.v1.UpdateTodosSuccess":                                     {1, 2, 3},
	"agent.v1.UpdateTodosError":                                       {1},
	"agent.v1.ReadTodosToolCall":                                      {1, 2},
	"agent.v1.ReadTodosArgs":                                          {1, 2},
	"agent.v1.ReadTodosResult":                                        {1, 2},
	"agent.v1.ReadTodosSuccess":                                       {1, 2},
	"agent.v1.ReadTodosError":                                         {1},
	"agent.v1.ReadLintsToolCall":                                      {1, 2},
	"agent.v1.ReadLintsToolArgs":                                      {1},
	"agent.v1.ReadLintsToolResult":                                    {1, 2},
	"agent.v1.ReadLintsToolSuccess":                                   {1, 2, 3},
	"agent.v1.ReadLintsToolError":                                     {1},
	"agent.v1.FileDiagnostics":                                        {1, 2, 3},
	"agent.v1.DiagnosticItem":                                         {1, 2, 3, 4, 5, 6},
	"agent.v1.DiagnosticRange":                                        {1, 2},
	"agent.v1.RequestContextPartReferences":                           {1, 2, 3, 4, 5, 6, 7, 8, 9},
	"agent.v1.RequestContextRulesPart":                                {1, 2, 3},
	"agent.v1.RequestContextSkillsPart":                               {1, 2},
	"agent.v1.RequestContextSubagentsPart":                            {1},
	"agent.v1.RequestContextMcpsPart":                                 {1, 2},
}

func agentContent(message, field string) bool {
	switch message {
	case agentBlobText:
		return field == "text"
	case "agent.v1.AgentRunRequest", "agent.v1.PrewarmRequest":
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
	case "agent.v1.RequestContextRulesPart":
		return field == "cloud_rule"
	case "agent.v1.ShellSuccess", "agent.v1.ShellFailure":
		return field == "stdout" || field == "stderr" || field == "interleaved_output" || field == "output_head" || field == "output_tail"
	case "agent.v1.ReadSuccess", "agent.v1.ReadToolSuccess":
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
	case "agent.v1.AssistantMessage", "agent.v1.ThinkingMessage":
		return field == "text"
	case "agent.v1.TodoItem", "agent.v1.AgentSkill", "agent.v1.GrepContentMatch":
		return field == "content"
	case "agent.v1.ConversationSummary":
		return field == "summary"
	case "agent.v1.ConversationPlan":
		return field == "plan"
	case "agent.v1.ShellCommand", "agent.v1.TerminalMetadata.Command":
		return field == "command"
	case "agent.v1.ShellOutput":
		return field == "stdout" || field == "stderr"
	case "agent.v1.McpInstructions":
		return field == "instructions"
	case "agent.v1.CustomSubagent":
		return field == "prompt" || field == "description"
	case "agent.v1.GitRepoInfo":
		return field == "status"
	case "agent.v1.Diagnostic", "agent.v1.DiagnosticItem":
		return field == "message"
	case "agent.v1.SkillDescriptor":
		return field == "description"
	case "agent.v1.ShellArgs":
		return field == "command" || field == "simple_commands" || field == "description"
	case "agent.v1.EditArgs":
		return field == "stream_content"
	case "agent.v1.EditSuccess":
		return field == "diff_string" || field == "before_full_file_content" || field == "after_full_file_content"
	}
	return false
}

// Inline prompts are independent text, not file edits or content-addressed
// history. Identifiers, map keys, integrity-bound tool results, and blob
// projections retain their immutable policy.
func agentWritableText(message, field string) bool {
	switch message {
	case "agent.v1.UserMessage":
		return field == "text" || field == "rich_text" || field == "subagent_system_reminder" || field == "forked_context"
	case "agent.v1.AgentRunRequest", "agent.v1.PrewarmRequest":
		return field == "custom_system_prompt"
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
