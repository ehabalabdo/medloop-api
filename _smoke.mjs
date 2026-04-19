import('./src/routes/auth.js').then(()=>{
  return import('./src/routes/appointments.js');
}).then(()=>{
  return import('./src/routes/reports.js');
}).then(()=>{
  return import('./src/routes/hr.js');
}).then(()=>{
  console.log('ALL_OK');
}).catch(e=>{
  console.error('FAILED:', e.message);
  process.exit(1);
});
