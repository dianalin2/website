/** @jsx jsx */
import { Box, Styled, jsx } from 'theme-ui'

import Navbar from './navbar'
import SEO from './seo'

const Layout = ({ children }) => {
  return (
    <Styled.root>
      <SEO />
      <Navbar />
      <Box as='main'>
        {children}
      </Box>
    </Styled.root>
  )
}

export default Layout
