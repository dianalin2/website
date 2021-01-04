/** @jsx jsx */
import { Box, Button, Flex, Grid, jsx } from 'theme-ui'
import { graphql } from 'gatsby'

import Layout from '../components/layout'
import Hero from '../components/hero'
import Container from '../components/container'
import LectureCard from '../components/lecturecard'
import CardGrid from '../components/cardgrid'

const fuseOptions = {
  keys: [{name: 'title', weight: 2}, 'body'],
  threshold: 0.4,
  minMatchCharLength: 3,
}

const Presentations = ({ data }) => {
  const {
    allLecturesYaml: {
      nodes: lectures,
    },
    allLectureFoldersYaml: {
      nodes: lectureFolders,
    },
  } = data

  return (
    <Layout seo={{ title: 'Presentations' }}>
      <Hero title='Presentations'
        subtitle='We give weekly presentations on a variety of interesting topics.'
      />
      <Container>
        <Grid
          gap={4}
          sx={{
            justifyItems: 'stretch',
            mb: 4
          }}
        >
          <Flex
            sx={{
              flexDirection: ['column', null, 'row'],
            }}
          >
            <Button
              sx={{
                mr: [0, null, 3],
                mb: [3, null, 0],
              }}
              as='a'
              href={lectureFolders[0].link}
              target='_blank'
              rel='nofollow noopener noreferrer'
            >
                Presentations ({lectureFolders[0].label})
            </Button>
            <Box sx={{ position: 'relative' }}>
              <Button
                sx={{
                  width: '100%',
                  '&:focus + *, & + :focus-within': {
                    visibility: 'visible',
                    opacity: 1,
                  },
                }}
              >
                Old Presentations
              </Button>
              <Box
                sx={{
                  visibility: 'hidden',
                  opacity: 0,
                  position: 'absolute',
                  top: 'calc(100% + 0.5rem)',
                  width: '100%',
                  bg: 'primary',
                  borderRadius: 4,
                  py: 2,
                  zIndex: 999,
                  transition: '0.2s linear',
                }}
              >
                {lectureFolders.slice(1).map((folder, i) => (
                  <Box
                    key={i}
                    as='a'
                    sx={{
                      display: 'block',
                      textDecoration: 'none',
                      color: 'background',
                      px: 3,
                      py: 2,
                      '&:hover, &:focus': {
                        bg: 'secondary',
                      }
                    }}
                    href={folder.link}
                    target='_blank'
                    rel='nofollow noopener noreferrer'
                  >
                    {folder.label}
                  </Box>
                ))}
              </Box>
            </Box>
          </Flex>
          <CardGrid items={lectures} Card={LectureCard} fuseOptions={fuseOptions}/>
        </Grid>
      </Container>
    </Layout>
  )
}

export default Presentations

export const query = graphql`
  query Lectures {
    allLecturesYaml(sort: {fields: date, order: ASC}) {
      nodes {
        title
        level
        date(formatString: "YYYY-MM-DD")
        body
        link
      }
    }
    allLectureFoldersYaml(sort: {fields: label, order: DESC}) {
      nodes {
        link
        label
      }
    }
  }
`
