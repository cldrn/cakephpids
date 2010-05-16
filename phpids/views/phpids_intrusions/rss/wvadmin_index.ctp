<?php
$this->set('documentData', array(
        'xmlns:dc' => 'http://purl.org/dc/elements/1.1/'));

    $this->set('channelData', array(
        'title' => __("PHPIDS INTRUSIONS RSS FEED", true),
        'link' => $html->url('/', true),
        'description' => __("Latest attacks.", true),
        'language' => 'en-us'));

foreach ($alerts as $alert) {
        $postTime = strtotime($alert['PhpidsIntrusion']['created']);
 
        $postLink = array(
            'controller' => 'phpids_intrusions',
            'action' => 'view',
            $alert['PhpidsIntrusion']['id']);
        
        // This is the part where we clean the body text for output as the description 
        // of the rss item, this needs to have only text to make sure the feed validates
        $bodyText = "{$alert['PhpidsIntrusion']['page']}-{$alert['PhpidsIntrusion']['ip']}:{$alert['PhpidsIntrusion']['impact']}";

 
        echo  $rss->item(array(), array(
            'title' => $bodyText,
            'link' => $postLink,
            'guid' => array('url' => $postLink, 'isPermaLink' => 'true'),
            'description' =>  $bodyText,
            'dc:creator' => "Websec.ca",
            'pubDate' => $alert['PhpidsIntrusion']['created']));
    }
?>
