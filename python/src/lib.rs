use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use servo::{ServoBuilder, SoftwareRenderingContext, WebViewBuilder};
use std::rc::Rc;
use url::Url;

/// Python wrapper around Bumble Bee's Servo web engine.
#[pyclass]
struct Browser {
    servo: servo::Servo,
    context: Rc<dyn servo::RenderingContext>,
    webview: servo::WebView,
}

#[pymethods]
impl Browser {
    #[new]
    #[pyo3(signature = (width=1280, height=720))]
    fn new(width: u32, height: u32) -> PyResult<Self> {
        let context = SoftwareRenderingContext::new(dpi::PhysicalSize::new(width, height))
            .map_err(|e| PyRuntimeError::new_err(format!("failed to create rendering context: {e:?}")))?;
        let context: Rc<dyn servo::RenderingContext> = Rc::new(context);
        let servo = ServoBuilder::default().build();
        let webview = WebViewBuilder::new(&servo, context.clone()).build();
        Ok(Self { servo, context, webview })
    }

    /// Load a URL into the current WebView.
    fn load(&self, url: &str) -> PyResult<()> {
        let parsed = Url::parse(url)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid URL: {e}")))?;
        self.webview.load(parsed);
        Ok(())
    }

    /// Paint the current WebView into its software rendering surface.
    fn paint(&self) {
        self.webview.paint();
    }

    /// Return the engine's package version.
    #[staticmethod]
    fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}

#[pymodule]
fn bumble_bee(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Browser>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
