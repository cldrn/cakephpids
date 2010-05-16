<?php
/*
* PHPIDS Configuration 
* -DONT FORGET TO CHANGE THE BASE PATH!
*/
    $config['Phpids']['base_path']="<your absolute path>/app/plugins/phpids/vendors/phpids/";
    $config['Phpids']['notification_email']="your@email.com";
    $config['Phpids']['production_mode']=true;
    $config['Phpids']['ban_duration']=30; /* Ban duration in days */
    $config['Phpids']['reaction_threshold_log']=3;
    $config['Phpids']['reaction_threshold_warn']=15;
    $config['Phpids']['reaction_threshold_mail']=50;
    $config['Phpids']['reaction_threshold_kill']=150;

?>
