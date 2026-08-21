const http = require('http');
http.get('http://localhost:9999/admin/api/settings', (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => console.log(data));
});
