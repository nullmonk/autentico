const hiddenSettingsTabs = ["1", "2"];
const items = [{key: "1"}, {key: "2"}, {key: "3"}];
console.log(items.filter(tab => !hiddenSettingsTabs.includes(tab.key)));
