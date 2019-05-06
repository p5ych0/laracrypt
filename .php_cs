<?php

$finder = PhpCsFixer\Finder::create()
    ->exclude('bootstrap/cache')
    ->exclude('storage')
    ->exclude('vendor')
    ->in(__DIR__)
    ->name('*.php')
    ->notName('*.blade.php')
    ->notPath('app/Foundation/helpers.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

return PhpCsFixer\Config::create()
    ->setRiskyAllowed(true)
    ->setCacheFile(__DIR__.'/.php_cs.cache')
    ->setRules(include("./csf"))
    ->setFinder($finder);