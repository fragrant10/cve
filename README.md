# cve

DBHcms v1.2.0

CVE-2020-19877 
DBHcms v1.2.0 has a directory traversal vulnerability as there is no directory control function in directory /dbhcms/. A remote unauthenticated attacker can exploit this vulnerability to obtain server-sensitive information.


CVE-2020-19878
DBHcms v1.2.0 has a sensitive information leaks vulnerability as there is no security access control in /dbhcms/ext/news/ext.news.be.php, A remote unauthenticated attacker can exploit this vulnerability to get path information.


CVE-2020-19879
DBHcms v1.2.0 has a stored xss vulnerability as there is no security filter of $_GET['dbhcms_pid'] variable in dbhcms\page.php line 107.


CVE-2020-19880
DBHcms v1.2.0 has a stored xss vulnerability as there is no htmlspecialchars function form 'Name' in dbhcms\types.php, A remote unauthenticated attacker can exploit this vulnerability to hijack other users.


CVE-2020-19881
DBHcms v1.2.0 has a reflected xss vulnerability as there is no security filter in dbhcms\mod\mod.selector.php line 108 for $_GET['return_name'] parameter, A remote authenticated with admin user can exploit this vulnerability to hijack other users.


CVE-2020-19882
DBHcms v1.2.0 has a stored xss vulnerability as there is no htmlspecialchars function for 'menu_description' variable in dbhcms\mod\mod.menus.edit.php line 83 and in dbhcms\mod\mod.menus.view.php line 111, A remote authenticated with admin user can exploit this vulnerability to hijack other users.


CVE-2020-19883
DBHcms v1.2.0 has a stored xss vulnerability as there is no security filter in dbhcms\mod\mod.users.view.php line 57 for user_login, A remote authenticated with admin user can exploit this vulnerability to hijack other users.


CVE-2020-19884
DBHcms v1.2.0 has a stored xss vulnerability as there is no htmlspecialchars function in dbhcms\mod\mod.domain.edit.php line 119.


CVE-2020-19885
DBHcms v1.2.0 has a stored xss vulnerability as there is no htmlspecialchars function for '$_POST['pageparam_insert_name']' variable in dbhcms\mod\mod.page.edit.php line 227, A remote authenticated with admin user can exploit this vulnerability to hijack other users.


CVE-2020-19886
DBHcms v1.2.0 has no CSRF protection mechanism,as demonstrated by CSRF for an /index.php?dbhcms_pid=-80&deletemenu=9 can delete any menu.


CVE-2020-19887
DBHcms v1.2.0 has a stored XSS vulnerability as there is no htmlspecialchars function for '$_POST['pageparam_insert_description']' variable in dbhcms\mod\mod.page.edit.php line 227, A remote authenticated with admin user can exploit this vulnerability to hijack other users.


CVE-2020-19888
DBHcms v1.2.0 has an unauthorized operation vulnerability because there's no access control at line 175 of dbhcms\page.php for empty cache operation. This vulnerability can be exploited to empty a table.


CVE-2020-19889
DBHcms v1.2.0 has no CSRF protection mechanism,as demonstrated by CSRF for index.php?dbhcms_pid=-70 can add a user.


CVE-2020-19890
DBHcms v1.2.0 has an Arbitrary file read vulnerability in dbhcms\mod\mod.editor.php $_GET['file'] is filename,and as there is no filter function for security, you can read any file's content.


CVE-2020-19891

DBHcms v1.2.0 has an Arbitrary file write vulnerability in dbhcms\mod\mod.editor.php $_POST['updatefile'] is filename and $_POST['tinymce_content'] is file content, there is no filter function for security. A remote authenticated admin user can exploit this vulnerability to get a webshell.