/** @jsx jsx */
import { Box, Button, Flex, Grid, Heading, jsx } from 'theme-ui'
import { graphql } from 'gatsby'
import Img from 'gatsby-image'
import scrollTo from 'gatsby-plugin-smoothscroll'

import Layout from '../components/layout'
import Container from '../components/container'

import CircuitBoard from '../images/circuit-board.svg'

const Index = ({ data }) => {
  const {
    site: {
      siteMetadata: {
        description,
      },
    },
    file: {
      childImageSharp: {
        fluid: image,
      },
    },
  } = data
  return (
    <Layout>
      <Flex
        sx={{
          flexDirection: 'row',
          alignItems: 'stretch',
          justifyContent: 'center',
          minHeight: '100vh',
          '& > *': {
            flex: '1',
            pt: theme => theme.sizes.navbar,
            pb: '0.5rem',
            px: ['2rem', '3rem', '4rem'],
          },
        }}
      >
        <Flex
          sx={{
            bg: ['altBackground', null, 'background'],
            backgroundImage: [`url(${CircuitBoard})`, null, 'none'],
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'flex-start',
          }}
        >
          <Grid
            gap={[2, 3, 4]}
            sx={{
              justifyItems: 'start',
            }}
          >
            <Heading
              as='h1'
              sx={{
                fontSize: [5, 6, 7],
              }}
            >
              TJHSST Computer Security Club
            </Heading>
            <Heading
              as='h2'
              sx={{
                color: 'primary',
                fontSize: [2, 3, 4],
              }}
            >
              {description}
            </Heading>
            <Button onClick={() => scrollTo('#about')}>Learn More</Button>
          </Grid>
        </Flex>
        <Flex
          sx={{
            display: ['none', null, 'flex'],
            flex: '1',
            bg: 'altBackground',
            backgroundImage: `url(${CircuitBoard})`,
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'stretch',
          }}
        >
          <Box>
            <Img fluid={image} alt='TJCSC at Lockheed Martin CYBERQUEST 2019'
              sx={{
                borderRadius: 4,
                mb: 1,
              }}
            />
            TJCSC at Lockheed Martin CYBERQUEST 2019
          </Box>
        </Flex>
      </Flex>
      <Container id='about'>
        <Heading as='h1'>
          About
        </Heading>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed justo lorem, efficitur at interdum in, laoreet sit amet mi. Quisque sollicitudin egestas nulla, non porta ligula tristique eget. Nullam faucibus dictum urna, et hendrerit mi hendrerit et. Vivamus fringilla mi nibh, vel efficitur ipsum dictum et. Nulla lectus magna, sollicitudin ut orci sit amet, congue venenatis lectus. Proin luctus varius nisi vel pretium. Praesent leo justo, fringilla et tempus quis, congue at urna. Fusce vulputate finibus sapien varius convallis.        </p>
        <p>Mauris consequat nec nisl ut semper. Donec at velit turpis. Quisque euismod lacus sed risus gravida vulputate. Aliquam et consequat ex, vel vulputate est. Interdum et malesuada fames ac ante ipsum primis in faucibus. Vivamus a pulvinar lorem, sit amet malesuada arcu. Nunc dapibus enim diam, sit amet sagittis sapien luctus et. In hac habitasse platea dictumst. Phasellus fermentum lacus quis ex consequat ornare. Suspendisse mi velit, interdum a lacus a, faucibus commodo leo. Curabitur dignissim lorem ac tellus vulputate lacinia id lobortis nisi. Duis rutrum, est id fringilla venenatis, diam velit pellentesque orci, id fringilla lacus diam nec leo. Curabitur nec leo egestas risus lacinia finibus.</p>
        <p>Nunc quis rutrum nulla. Donec in urna maximus turpis volutpat finibus vel sed leo. Vivamus maximus ex id gravida maximus. Nulla facilisi. Morbi sollicitudin a tellus ut semper. Vivamus sapien ex, dignissim ut nulla eget, posuere fringilla risus. Aliquam non tempor ante. Ut laoreet non enim imperdiet aliquam. Mauris ullamcorper dictum augue, sit amet sodales est tempus ut. Duis ex nibh, semper a suscipit eu, posuere ac massa.</p>
        <p>Donec ullamcorper ante odio, quis tincidunt metus finibus et. Donec metus turpis, mattis quis varius id, facilisis ut lorem. Proin metus justo, placerat eget lacus vitae, rutrum varius tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum sem enim, euismod non lacus a, sagittis tempor orci. Pellentesque tristique nec dolor eget auctor. Pellentesque ornare, eros at vulputate commodo, nibh metus tristique nunc, et sollicitudin magna arcu sit amet lacus. Morbi non venenatis quam. Morbi justo est, imperdiet id aliquam eget, congue vitae nulla. Cras at interdum nibh. Nunc molestie a mi ac porta. Quisque condimentum, sem vitae ultricies dapibus, tellus leo scelerisque sapien, non vestibulum augue diam in erat. Suspendisse rutrum ullamcorper mi, at maximus ex hendrerit nec. Proin lorem nunc, efficitur hendrerit sagittis nec, rhoncus sit amet justo. Aenean tristique ipsum vestibulum felis fringilla malesuada. Praesent semper tellus et ornare pulvinar.</p>
        <p>Nunc eu orci convallis, egestas erat eget, semper massa. Etiam ac neque suscipit, iaculis est a, eleifend odio. Morbi tristique faucibus arcu. Integer facilisis tortor luctus, sagittis ipsum id, feugiat elit. Nunc faucibus erat quis maximus viverra. Pellentesque iaculis consectetur augue, in condimentum dolor facilisis id. Donec eget ligula vel magna interdum semper et at purus. Nunc ornare quis sapien at gravida. Proin porta purus vel metus tincidunt iaculis. Morbi sapien dolor, dapibus at egestas et, cursus quis turpis. Proin sollicitudin molestie mattis. Nulla vehicula rutrum massa in facilisis. Phasellus feugiat ante et sem consectetur, eu tincidunt metus scelerisque. Phasellus dapibus arcu eu lorem lobortis, a bibendum sem dapibus. Suspendisse a ante at eros laoreet ultrices.</p>
      </Container>
    </Layout>
  )
}

export default Index

export const query = graphql`
  query Home {
    site {
      siteMetadata {
        description
      }
    }
    file(relativePath: {eq: "cyberquest.png"}) {
      childImageSharp {
        fluid {
          ...GatsbyImageSharpFluid
        }
      }
    }
  }
`
