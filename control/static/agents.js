(()=>{
let screen='agentops';
function show(hash=''){const url='/_kt88/'+screen+'/'+hash;$('agent-native-frame').src=url;$('agent-native-link').href=url;document.querySelectorAll('[data-agent-screen]').forEach(b=>b.classList.toggle('active',b.dataset.agentScreen===screen))}
window.loadAgents=async()=>show();window.editAgent=async id=>{screen='agentops';show('#worker='+encodeURIComponent(id))};document.querySelectorAll('[data-agent-screen]').forEach(b=>b.onclick=()=>{screen=b.dataset.agentScreen;show()});
})();
