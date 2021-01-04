/** @jsx jsx */
import { Box, Close, Flex, Heading, IconButton, jsx } from 'theme-ui'
import { graphql } from 'gatsby'
import { useCallback, useState } from 'react'
import { IoList } from 'react-icons/io5'
import { MDXRenderer } from 'gatsby-plugin-mdx'
import { Global } from '@emotion/core'

import Layout from '../components/layout'
import Hero from '../components/hero'
import Container from '../components/container'
import TableOfContents from '../components/toc'
import { prismArrangement } from '../gatsby-plugin-theme-ui/prism'

const Writeup = ({ data: { mdx: post } }) => {
  const {
    frontmatter: {
      title,
      date,
    },
    excerpt,
    body,
    tableOfContents: {
      items: toc,
    },
  } = post

  const [tocOpen, setTocOpen] = useState(false)

  return (
    <Layout seo={{ title, description: excerpt }} >
      <Global
        styles={theme => (prismArrangement(theme))}
      />
      <IconButton
        onClick={useCallback(() => {setTocOpen(open => !open)}, [])}
        aria-label='Table of Contents'
        sx={{
          display: ['block', null, 'none'],
          position: 'fixed',
          bottom: [3, 4],
          left: [3, 4],
          bg: 'primary',
          color: 'background',
          zIndex: 999,
          cursor: 'pointer',
        }}
      >
        <IoList />
      </IconButton>
      <Container>
        <Flex>
          <Flex
            sx={{
              flexDirection: 'column',
              bg: 'altBackground',
              width: [250, null, 300],
              borderRadius: [0, null, 5],
              overflow: 'hidden',
              position: 'sticky',
              top: theme => `calc(${theme.sizes.navbar}px + 1rem)`,
              // lmfao
              maxHeight: theme => `calc(100vh - 2 * ${theme.sizes.navbar}px - 2rem)`,
              '& ul': {
                m: 0,
                listStyle: 'none',
                pl: 3,
                '& li': {
                  py: 2,
                },
              },
              '& a': {
                color: 'text',
                '&:hover': {
                  filter: 'brightness(0.9)',
                },
              },
              '@media (max-width: 56em)': {
                position: 'fixed',
                top: 0,
                right: 0,
                zIndex: 999,
                height: '100vh',
                maxHeight: 'none',
                transform: tocOpen ? 'translateX(0)' : 'translateX(100%)',
                transition: 'transform 200ms linear',
                boxShadow: '-6px 0px 24px rgba(0,0,0,.15)',
              },
            }}
          >
            <Box
              sx={{
                p: 4,
                bg: 'lightBackground',
                color: 'text',
              }}
            >
              <Close
                onClick={useCallback(() => {setTocOpen(false)}, [])}
                sx={{
                  cursor: 'pointer',
                  mr: 'auto',
                  mb: 3,
                  display: ['inline-flex', null, 'none'],
                }}
              />
              <Heading as='h1'
                sx={{
                  fontSize: 4,
                  my: 'auto',
                  mr: 'auto'
                }}
              >
                Table of Contents
              </Heading>
            </Box>
            <Box
              sx={{
                overflow: 'auto',
                p: 4,
              }}
            >
              <TableOfContents items={toc} sx={{ pl: '0 !important' }} />
            </Box>
          </Flex>
          <Box
            sx={{
              m: 'auto',
              pl: [0, null, 5],
              '& > *': {
                px: '0 !important'
              },
            }}
          >
            <Hero title={title} subtitle={'Published on ' + date}
              sx={{ maxWidth: 'writeup' }}
            />
            <Container
              sx={{
                maxWidth: 'writeup',
                '& a.anchor': {
                  fill: theme => theme.colors.text,
                },
              }}
            >
              <MDXRenderer>{body}</MDXRenderer>
            </Container>
          </Box>
        </Flex>
      </Container>
    </Layout>
  )
}

export default Writeup

export const query = graphql`
  query Writeup ($path: String!) {
    mdx(frontmatter: { slug: { eq: $path } }) {
      frontmatter {
        date(formatString: "YYYY-MM-DD")
        title
      }
      excerpt
      body
      tableOfContents(maxDepth: 6)
    }
  }
`
