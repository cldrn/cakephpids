The following attack has been detected by PHPIDS


IP: <?php e($attack['ip']); ?>

Date: <?php e(date("F M Y", strtotime('now'))); ?>

Impact: <?php e($attack['impact']); ?>

Affected tags:  <?php e($attack['tags']); ?>

Affected parameters: <?php e($attack['name']); ?>

Request URI: <?php e($attack['value']); ?>

Origin: <?php e($attack['page']); ?>
