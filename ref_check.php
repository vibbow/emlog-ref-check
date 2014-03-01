<?php
/*
* Plugin Name: CSRF保护脚本
* Version: 1.2
* Description: 防止跨站请求伪造攻击
* Author: vibbow
* Author Email: vibbow@gmail.com
* Author URL: http://vsean.net/
*/
!defined('EMLOG_ROOT') && exit('access deined!');
define('REF_CHECK_DEBUG', FALSE);

// 如果访问的文件不是 index.php
// 则访问的既不是前台，也不是后台首页
// 只可能是后台设置页面
if (pathinfo($_SERVER['SCRIPT_FILENAME'], PATHINFO_BASENAME) != 'index.php') {
	ref_check();
}

function ref_check() {
	$referer_url = isset($_SERVER['HTTP_REFERER']) ? filter_var($_SERVER['HTTP_REFERER'], FILTER_VALIDATE_URL) : NULL;

	//如果POST提交没有任何来源，则直接拒绝
	if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($referer_url)) {
		header('HTTP/1.0 403 Forbidden');
		echo '<h1>Forbidden</h1>';
		exit();
	}

	//只验证POST提交，不验证GET提交
	if ($_SERVER['REQUEST_METHOD'] === 'POST') {
		$referer_host = parse_url($referer_url, PHP_URL_HOST);
		$referer_path = parse_url($referer_url, PHP_URL_PATH);
		if (substr($referer_path, -1) === '/') {
			$referer_path .= 'index.php';
		}
		$referer_path = dirname($referer_path);

		$admin_url = 'http://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
		$admin_host = parse_url($admin_url, PHP_URL_HOST);
		$admin_path = parse_url($admin_url, PHP_URL_PATH);
		if (substr($admin_path, -1) === '/') {
			$admin_path .= 'index.php';
		}
		$admin_path = dirname($admin_path);

		if (REF_CHECK_DEBUG) {
			echo "Ref URL: {$referer_url}<br />\r\n";
			echo "Ref Host: {$referer_host}<br />\r\n";
			echo "Ref Path: {$referer_path}<br />\r\n";
			echo "Admin Host: {$admin_host}<br />\r\n";
			echo "Admin Path: {$admin_path}<br />\r\n";
		}

		//如果来源地址和后台地址不符，则拒绝
		if ($admin_host != $referer_host ||
			$admin_path != $referer_path) {
			header('HTTP/1.0 403 Forbidden');
			echo '<h1>Forbidden</h1>';
			exit();
		}
	}
}