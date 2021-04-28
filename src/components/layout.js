/** @jsx jsx */
import { Flex, Styled, jsx } from 'theme-ui'
import { Global } from '@emotion/core'
import Navbar from './navbar'
import Footer from './footer'
import SEO from './seo'
import { motion } from 'framer-motion'

const Layout = ({ seo, children, ...props }) => {
  return (
    <Styled.root {...props}>
      <Global
        styles={(theme) => ({
          body: {
            '&, *': {
              scrollbarColor: `${theme.colors.primary} ${theme.colors.navbar}`,
              scrollbarWidth: 'thin',
              '::-webkit-scrollbar': {
                background: theme.colors.navbar,
                width: 5,
                height: 5,
              },
              '::-webkit-scrollbar-thumb': {
                background: theme.colors.primary,
              },
            },
          },
        })}
      />
      <SEO {...seo} />
      <Navbar />
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <Flex
          as='main'
          sx={{
            flexDirection: 'column',
            justifyContent: 'stretch',
            minHeight: (theme) => `calc(100vh - ${theme.sizes.footer}px)`,
          }}
        >
          {children}
        </Flex>
        <Footer />
      </motion.div>
    </Styled.root>
  )
}

export default Layout
