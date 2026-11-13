from scanner.models import ApplicationModel, FileModel
from scanner.tamper_analyzer import analyze_tamperability


def _f(path: str, content: str) -> FileModel:
    name = path.split("/")[-1]
    ext = "." + name.split(".")[-1] if "." in name else ""
    return FileModel(
        file_name=name,
        file_path=path,
        file_type="Unknown",
        extension=ext,
        file_size=len(content.encode("utf-8")),
        content=content,
        read_error=None,
    )


def test_java_tamper_detects_debug_admin_and_cookie_flags():
    java_src = """
public class SecurityConfig {
  boolean isAdmin = true;
  String role = "admin";
  void cfg(Cookie c) {
    c.setSecure(false);
    c.setHttpOnly(false);
  }
}
"""
    model = ApplicationModel(project_path="demo", files=[_f("src/main/java/SecurityConfig.java", java_src)], file_count=1)
    analyze_tamperability(model)
    kinds = {t.type for t in model.tamperability}
    assert "Hardcoded Admin Flag" in kinds
    assert "Hardcoded Admin Role" in kinds
    assert "Insecure Cookie Flag" in kinds
    assert "HttpOnly Disabled Cookie" in kinds


def test_java_properties_tamper_detects_debug_cors_cookie():
    props = """
debug=true
cors.allowed-origins=*
server.servlet.session.cookie.secure=false
server.servlet.session.cookie.http-only=false
"""
    model = ApplicationModel(project_path="demo", files=[_f("src/main/resources/application.properties", props)], file_count=1)
    analyze_tamperability(model)
    kinds = {t.type for t in model.tamperability}
    assert "Debug Mode Enabled" in kinds
    assert "Permissive CORS" in kinds
    assert "Insecure Cookie Flag" in kinds
    assert "HttpOnly Disabled Cookie" in kinds

