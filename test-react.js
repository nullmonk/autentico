const hiddenSettingsTabs = ["1", "2"];
const items = [{key: "1"}, {key: "2"}, {key: "3"}];
const filtered = items.filter(tab => !hiddenSettingsTabs.includes(tab.key));
console.log(filtered);
