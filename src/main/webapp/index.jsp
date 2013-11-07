<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>haha</title>
    <script type="text/javascript" src="js/jquery-2.0.3.js"></script>
    <script type="text/javascript" src="js/jsrender.js"></script>
</head>
<body>
home
<li><a href="/j_spring_security_logout">Log Out</a></li>
<div id="result"></div>
<script id="t" type="text/x-jsrender">
{{:name}}
{{sec "hasRole('ROLE_USER')"}}
user
{{/sec}}
{{sec "hasRole('ROLE_USER')"}}
admin
{{/sec}}
{{sec "hasRole('ROLE_HAHA')"}}
haha
{{/sec}}
{{sec "hasPermission(1, 'com.datayes.paas.Foo', 'READ')"}}
read permission
{{/sec}}
{{sec "hasPermission(1, 'com.datayes.paas.Foo', 'WRITE')"}}
write permission
{{/sec}}
</script>
<script>
$.views.tags("sec", function(expression) {
    var id = 'id-' + Math.floor(Math.random() * 0x1000000);
    var self = this;
    $.get('/security?access=' + expression).done(function() {
        $('#' + id).replaceWith(self.tagCtx.render());
    }).error(function() {
        $('#' + id).remove();
    });
    return '<sec id=' + id + '/>';
});
$(function() {
    var template = $.templates("#t");
    var htmlOutput = template.render({name: 'kkk'});
    $("#result").html(htmlOutput);
});
</script>
</body>
</html>
