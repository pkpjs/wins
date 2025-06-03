<%@ page import="java.io.*" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<html>
<head>
  <title>Payload 상태</title>
</head>
<body>
<%
    String dirPath = application.getRealPath("/");
    File dir = new File(dirPath);
    File[] serFiles = dir.listFiles(new FilenameFilter() {
        public boolean accept(File dir, String name) {
            return name.toLowerCase().endsWith(".ser");
        }
    });

    if (serFiles != null && serFiles.length > 0) {
        String fullUrl = request.getRequestURL().toString().replace(request.getServletPath(), "") + "/loadpayload.jsp";
        out.println("✅ <a href=\"" + fullUrl + "\" target=\"_blank\">loadpayload.jsp 실행</a><br><br>");

        for (File serFile : serFiles) {
            if (serFile.delete()) {
                out.println("🗑️ 삭제됨: " + serFile.getName() + "<br>");
            } else {
                out.println("❌ 삭제 실패: " + serFile.getName() + "<br>");
            }
        }
    } else {
        out.println("📭 .ser 파일이 없습니다.");
    }
%>
</body>
</html>
