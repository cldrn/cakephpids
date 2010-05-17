<?php 
/*
* Attacks/Intrusions
*
* PHPIDS (http://www.phpids.org)
* @author: Paulino Calderon <paulino@calderonpale.com>
*/
class PhpidsIntrusionsController extends PhpidsAppController {

    var $name='PhpidsIntrusions';
    var $components=array('RequestHandler','Email');    
    var $threshold; 
   
    /*
    * beforeFilter()
    * Loads PHPIDS configuration and checks if IP is banned
    */
    function beforeFilter() {

        parent::beforeFilter(); /* You may not need this. */

        /* Set plugin conf path according to version */
        $cakeVersion=Configure::version();
        if(strstr($cakeVersion,"1.2")) 
            $plugin_path='phpids';
        else if (strstr($cakeVersion,'1.3')) 
            $plugin_path='phpids.phpids';

        Configure::load($plugin_path);

        /* Get reaction threshold from Config */
        $this->threshold= array(
            'log'      => Configure::read('Phpids.reaction_threshold_log'),
            'warn'     => Configure::read('Phpids.reaction_threshold_warn'),
            'mail'     => Configure::read('Phpids.reaction_threshold_mail'),
            'kill'     => Configure::read('Phpids.reaction_threshold_kill')   
        );

        /* Check if IP exists in cache */
        $banDuration=Configure::read('Phpids.ban_duration');
        Cache::set(array('duration'=>"+$banDuration days"));
        $ipBanned=Cache::read('banned_ip_'.$this->getIP());
        
        /* This IP is banned! Exiting! */
        if($ipBanned==1 && Configure::read('Phpids.production_mode')) 
            exit();
    }

    /**
     * detect()
     * This function includes the IDS from vendors and runs the
     * detection routines on the request array.
     */
    function detect() {
        
        App::import('Vendor', 'Phpids.init', array('file' => 'phpids/IDS/Init.php'));
            
        /* add request url and user agent */
        $_REQUEST['IDS_request_uri'] = $_SERVER['REQUEST_URI'];
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $_REQUEST['IDS_user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        }       

        /* set include path for IDS  and store old one - PHPIDS needs this!*/
        $path = get_include_path();
        $phpids_basepath=Configure::read("Phpids.base_path");
        set_include_path($phpids_basepath); 
        
        /* initialize the PHPIDS and scan the REQUEST array */
        $this->init = IDS_Init::init($phpids_basepath.'IDS/Config/Config.ini.php');
        $ids = new IDS_Monitor($_REQUEST,$this->init);
        $result = $ids->run();

        /* Re-set old include path */
        set_include_path($path);

        /* React to the attack according to result */
        if (!$result->isEmpty()) {
            $this->react($result);
        }
    }

    /*
    * react(IDS_Report $result)
    * This function reacts to the attack according to impact
    */
    function react(IDS_Report $result) {
        
        $ip=$this->getIP();
        
        /* check and update attackers impact history */
        Cache::set(array('duration'=>'+30 days'));
        $impact=Cache::read('phpids_impact_'.$ip);
        $newImpact = $impact + $result->getImpact();
        Cache::set(array('duration'=>'+30 days'));
        Cache::write('phpids_impact_'.$ip,$newImpact);
        
        /* react to attack */
        if ($newImpact >= $this->threshold['kill']) {
            $this->idslog($result, 3, $newImpact);
            $this->idsmail($result, $newImpact);
            $this->idskill();
            return true;
        } else if ($newImpact >= $this->threshold['mail']) {
            $this->idslog($result, 2, $newImpact);
            $this->idsmail($result, $newImpact);
            return true;
        } else if ($newImpact >= $this->threshold['warn']) {
            $this->idslog($result, 1, $newImpact);
            return true;
        } else if ($newImpact >= $this->threshold['log']) {
            $this->idslog($result, 0, $newImpact);
            return true;
        } else {
            return true;
        }
    }

    /**
    * idslog($result, $reaction, $impact)
    * This function records the attack
    */
    function idslog($result, $reaction = 0, $impact=0) {

        $user = $this->Session->read('User.id')?$this->Session->read('User.id'):0;
        $ip=$this->getIP();
      
        foreach ($result as $event) {        
            $intrusion=$this->PhpidsIntrusion->create();
            
            $tags_serialized=implode(" ", $event->getTags());
            $data = array(
                'PhpidsIntrusion' => array(
                    'name'      => $event->getName(),
                    'value'     => stripslashes($event->getValue()),
                    'page'      => $_SERVER['REQUEST_URI'],
                    'userid'    => $user,
                    'session'   => session_id() ? session_id() : '0',
                    'ip'        => $ip,
                    'reaction'  => $reaction,
                    'impact'    => $impact,
                    'tags' => $tags_serialized
                )
            );
            $this->PhpidsIntrusion->save($data);
        }
    }

    /*
    * idsmail($result, $impact)
    * Emails the intrusion alert to admin
    */
    function idsmail($result, $impact) {
        
        $this->Email->template='intrusion_alert';
        $this->Email->sendAs='text';
        $this->Email->from='phpids@websec.ca';
        $this->Email->to=Configure::read("Phpids.notification_email");
        $this->Email->subject='PHPIDS Alert';
        
        $alert['ip']=$this->getIP();
        foreach ($result as $event) {        
            /*attack information*/
            $alert['tags']=implode(" ", $event->getTags());
            $alert['name']=$event->getName();
            $alert['impact']=$impact;
            $alert['value']=stripslashes($event->getValue());
            $alert['page']=$_SERVER['REQUEST_URI'];
        
            $this->set('attack',$alert);
            $this->Email->send();
        }     
    }

    /*
    * idskill()
    * Creates a file in the cache blacklisting the attackers IP
    */
    function idskill() {
        $ip=$this->getIP();
        $cacheFilename='banned_ip_'.$ip;
        $banDuration=Configure::read('Phpids.ban_duration'); 
        Cache::set(array('duration'=>"+$banDuration days"));
        $cacheValue=Cache::write($cacheFilename,1);      
    }

    /*
    * getIP()
    * Extracts IP from $_SERVER variable
    */
    function getIP() {
        $ip = ($_SERVER['SERVER_ADDR'] != '127.0.0.1') ?
                    $_SERVER['SERVER_ADDR'] :
                        (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ?
                            $_SERVER['HTTP_X_FORWARDED_FOR'] :
                                 '127.0.0.1');
        return $ip;
    }   
    
}
?>
