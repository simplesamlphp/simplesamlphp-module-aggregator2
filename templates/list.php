<?php

$this->includeAtTemplateBase('includes/header.php');
?>
    <h1><?php echo $this->t('{aggregator2:aggregator:header}'); ?></h1>

<?php
if (count($this->data['sources']) === 0) {
    echo "    <p>".$this->t('{aggregator2:aggregator:no_aggregators}')."</p>\n";
} else {
    echo "    <ul>";
    $sources = $this->data['sources'];
    foreach ($sources as $id => $source) {
        echo str_repeat(' ', 8)."<li>\n";
        echo str_repeat(' ', 12).'<a href="';
        echo $source['name'].'">'.htmlspecialchars($id)."</a>\n";
        echo str_repeat(' ', 12).'<a href="';
        echo $source['text'].'">['.$this->t('{aggregator2:aggregator:text}')."]</a>\n";
        echo str_repeat(' ', 12).'<a href="';
        echo $source['xml']."\">[XML]</a>\n";
        echo str_repeat(' ', 8)."</li>\n";
    }

    echo "    </ul>\n";
}

$this->includeAtTemplateBase('includes/footer.php');
