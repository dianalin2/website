/** @jsx jsx */
import { Flex, Styled, jsx } from 'theme-ui'

import Navbar from './navbar'
import Footer from './footer'
import SEO from './seo'

const Layout = ({ children }) => {
  return (
    <Styled.root>
      <SEO />
      <Navbar />
      <Flex
        as='main'
        sx={{
          flexDirection: 'column',
          justifyContent: 'stretch',
          minHeight: theme => `calc(100vh - ${theme.sizes.footer})`
        }}
      >
        {children}
      </Flex>
      <Footer />
    </Styled.root>
  )
}

export default Layout
