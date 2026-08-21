const tabs = [{key: "1"}, {key: "2"}];
const hiddenSettingsTabs = ["1"];
console.log(tabs.filter(tab => !hiddenSettingsTabs.includes(tab.key)));
