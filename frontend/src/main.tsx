import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { captureSetupToken } from './services/setupToken'

// The desktop app passes a first-run setup token in the URL; keep it out of
// the address bar and the router before anything renders.
captureSetupToken(window)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
