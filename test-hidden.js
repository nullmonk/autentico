const settings = { admin_ui_hidden_settings: "[\"1\"]" };
let hiddenSettingsTabs = [];
try {
  if (settings?.admin_ui_hidden_settings) {
    hiddenSettingsTabs = typeof settings.admin_ui_hidden_settings === "string"
      ? JSON.parse(settings.admin_ui_hidden_settings)
      : settings.admin_ui_hidden_settings;
  }
} catch (e) {
  console.error("Failed to parse admin_ui_hidden_settings", e);
}
console.log(hiddenSettingsTabs.includes("1"));
