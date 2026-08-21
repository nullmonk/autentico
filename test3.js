let hiddenSettingsTabs = [];
const settings = { admin_ui_hidden_settings: "[\"1\"]" };
if (settings?.admin_ui_hidden_settings) {
  hiddenSettingsTabs = typeof settings.admin_ui_hidden_settings === "string"
    ? JSON.parse(settings.admin_ui_hidden_settings)
    : settings.admin_ui_hidden_settings;
}
console.log(hiddenSettingsTabs);
