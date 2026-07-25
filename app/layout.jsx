import './globals.css'
import { ChainProvider } from './context/ChainProvider'
import { AlertProvider } from './context/AlertProvider'

export const metadata = {
  title: 'Rug Pull Detector',
  description: 'Analyze assets on multiple chains (EVM, Stellar/Soroban) for rug-pull risk and share public report pages with server-rendered previews.',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="min-h-screen text-white">
        <ChainProvider>
          <AlertProvider>
            {children}
          </AlertProvider>
        </ChainProvider>
      </body>
    </html>
  )
}
