import unittest
from monitor import events,health_event,get_devices,trusted_base,validate_config
CONFIG={'routers':[{'id':'one','model':'Archer A6','address':'test address'},{'id':'two','model':'Archer AX23'}]}
class MonitorTests(unittest.TestCase):
 def test_online_baseline_is_quiet(self):
  notifications,state=events(CONFIG,{'one':'online','two':'online'},{},100)
  self.assertEqual(notifications,[]);self.assertEqual(state['routers']['one']['state'],'online')
 def test_offline_and_recovery_only_once(self):
  _,old=events(CONFIG,{'one':'online','two':'online'},{},100)
  notices,down=events(CONFIG,{'one':'offline','two':'online'},old,200)
  self.assertEqual(len(notices),1);self.assertIn('Archer A6',notices[0]['title']);self.assertIn('test address',notices[0]['body'])
  notices,same=events(CONFIG,{'one':'offline','two':'online'},down,300);self.assertEqual(notices,[])
  notices,_=events(CONFIG,{'one':'online','two':'online'},same,400);self.assertEqual(len(notices),1);self.assertIn('снова в сети',notices[0]['title'])
 def test_first_offline_alerts_once(self):
  notices,state=events(CONFIG,{'one':'offline'},{},100);self.assertEqual(len(notices),1)
  self.assertEqual(events(CONFIG,{'one':'offline'},state,200)[0],[])
 def test_missing_or_unknown_is_not_offline(self):
  _,state=events(CONFIG,{'one':'online','two':'online'},{},100)
  notices,next_state=events(CONFIG,{'one':'unknown'},state,200)
  self.assertEqual(notices,[]);self.assertEqual(next_state['routers']['one']['state'],'online');self.assertEqual(next_state['routers']['two']['state'],'online')
 def test_cloud_failure_does_not_change_device_states(self):
  _,state=events(CONFIG,{'one':'online'},{},100)
  notices,failed=health_event(state,None,200);self.assertEqual(len(notices),1);self.assertEqual(failed['routers'],state['routers'])
  self.assertEqual(health_event(failed,None,300)[0],[])
 def test_expired_token_is_own_alert(self):
  notices,_=health_event({},-20651,100);self.assertIn('приостановлен',notices[0]['title'])
 def test_paginated_devices(self):
  def page(_,index):return {'deviceList':[{'deviceId':str(index),'status':index}],'totalNum':2}
  self.assertEqual(get_devices({},page),{'0':'offline','1':'online'})
 def test_untrusted_servers_blocked(self):
  for value in ['http://n-wap-gw.i.tplinkcloud.com','https://tplinkcloud.com.evil.test','https://x.tplinkcloud.com/path','https://user@x.tplinkcloud.com']:
   with self.assertRaises(ValueError):trusted_base(value)
 def test_duplicate_router_ids_rejected(self):
  with self.assertRaises(ValueError):validate_config({'session':{'token':'test','terminalId':'test','deviceUrl':'https://n-wap-gw.i.tplinkcloud.com'},'fcmToken':'test','routers':[{'id':'one','model':'a'},{'id':'one','model':'b'}]})
if __name__=='__main__':unittest.main()
