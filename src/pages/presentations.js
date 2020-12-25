/** @jsx jsx */
import { Box, Button, Flex, Grid, jsx } from 'theme-ui'
import { graphql } from 'gatsby'
import Fuse from 'fuse.js';

import Layout from '../components/layout'
import Hero from '../components/hero'
import Container from '../components/container'
import SearchBar from '../components/searchbar'
import LectureCard from '../components/lecturecard'
import { useCallback, useState } from 'react'

const debounce = (func, wait) => {
  let timeout

  return (...args) => {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }
    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }
}

const CardGrid = ({ lectures }) => {
  return (
    <Grid
      sx={{
        gridTemplateColumns: [
          'repeat(auto-fill, minmax(200px, 1fr))',  // better way to do this?
          null,
          'repeat(auto-fill, minmax(300px, 1fr))',
        ],
      }}
    >
      {lectures.map(({ node: lecture }, i) => (
        <LectureCard
          key={i}
          title={lecture.title}
          body={lecture.body}
          level={lecture.level}
          link={lecture.link}
          date={lecture.date}
        />
      ))}

    </Grid>
  )
}

const Presentations = ({ data }) => {
  const {
    allLecturesYaml: {
      edges: lectures,
    },
    allLectureFoldersYaml: {
      edges: lectureFolders,
    },
  } = data

  const { node: currentFolder } = lectureFolders[0]

  const [pattern, setPattern] = useState('')
  const [displayedLectures, setDisplayedLectures] = useState(lectures)

  const fuseOptions = {
    keys: [{name: 'node.title', weight: 2}, 'node.body'],
    threshold: 0.4,
  }
  const fuse = new Fuse(lectures, fuseOptions)

  const search = useCallback(debounce((value) => {
    const res = (value === '')
      ? lectures
      : fuse.search(value).map(val => val.item)
    setDisplayedLectures(res)
  }, 100), [])

  const onSearchAction = (e) => {
    setPattern(e.target.value)
    search(e.target.value)
  }

  return (
    <Layout>
      <Hero title='Presentations' />
      <Container>
        <Grid
          gap={4}
          sx={{
            justifyItems: 'stretch',
            marginBottom: 4
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
              href={currentFolder.link}
              target='_blank'
              rel='noopener noreferrer'
            >
                Presentations ({currentFolder.label})
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
                {lectureFolders.slice(1).map(({ node: folder }, i) => (
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
                    rel='noopener noreferrer'
                  >
                    {folder.label}
                  </Box>
                ))}
              </Box>
            </Box>
          </Flex>
          <SearchBar onChange={onSearchAction} value={pattern} />
          <CardGrid lectures={displayedLectures} />
        </Grid>
      </Container>
    </Layout>
  )
}

export default Presentations

export const query = graphql`
  query Lectures {
    allLecturesYaml {
      edges {
        node {
          title
          level
          date
          body
          link
        }
      }
    }
    allLectureFoldersYaml {
      edges {
        node {
          link
          label
        }
      }
    }
  }
`
