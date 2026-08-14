import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { SocProvider } from './SocContext'
import './index.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <SocProvider>
        <App />
      </SocProvider>
    </BrowserRouter>
  </StrictMode>,
)
