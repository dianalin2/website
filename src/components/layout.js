/** @jsx jsx */
import { Flex, Styled, jsx } from 'theme-ui'

import Navbar from './navbar'
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
        }}
      >
        {children}
      </Flex>
    </Styled.root>
  )
}

export default Layout
