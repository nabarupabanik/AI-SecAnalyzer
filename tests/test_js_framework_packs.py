from scanner.streaming_scan import stream_project_scan


def _drain(gen):
    model = None
    while True:
        try:
            next(gen)
        except StopIteration as ex:
            model = ex.value
            break
    return model


def test_js_express_req_get_source_detected(tmp_path):
    content = """
    const { exec } = require('child_process');
    app.get('/run', (req, res) => {
      exec(req.get('x-cmd'));
    });
    """
    (tmp_path / "express.js").write_text(content, encoding="utf-8")
    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None
    assert any(e.function == "child_process.exec" and e.tainted for e in model.process_events)


def test_js_fastify_source_and_render_sink_detected(tmp_path):
    content = """
    fastify.get('/p', async (request, reply) => {
      const name = request.query.name;
      res.render('home', { name });
    });
    """
    (tmp_path / "fastify.ts").write_text(content, encoding="utf-8")
    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None
    assert any(e.function == "express.res.render" and e.tainted for e in model.process_events)
