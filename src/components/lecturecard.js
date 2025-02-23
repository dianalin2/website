/** @jsx jsx */
import { Heading, Progress, Link, Text, Box, jsx } from 'theme-ui'
import { motion } from 'framer-motion'

import { cardAnimateProps } from '../animations/animations'
import datefmt from '../utils/datefmt'

const difficulty = {
  1: {
    color: '#AED1FE',
    display: 'Easy',
  },
  2: {
    color: '#FFDB78',
    display: 'Medium',
  },
  3: {
    color: '#D67C78',
    display: 'Hard',
  },
}

const LectureCard = ({
  body,
  date,
  level,
  title,
  link,
  guest = false,
  ...props
}) => {
  const { color, display } = difficulty[level]

  return (
    <Link
      href={link}
      sx={{
        textDecoration: 'none',
        display: 'flex',
      }}
      target='blank'
      rel='nofollow noopener noreferrer'
    >
      <motion.div
        {...cardAnimateProps()}
        {...props}
        sx={{
          flex: 'auto',
          display: 'flex',
          bg: 'lightBackground',
          borderRadius: 4,
          padding: 4,
          alignItems: 'stretch',
          flexDirection: 'column',
          justifyContent: 'space-between',
          cursor: 'pointer',
          '& > *': {
            flex: '0 1 auto',
          },
        }}
      >
        <Heading
          as='h1'
          sx={{
            fontSize: [3, 4, 5],
          }}
        >
          {title}
        </Heading>
        <Text
          sx={{
            fontSize: 1,
            marginTop: 2,
            color: color,
          }}
        >
          {datefmt(date)}
        </Text>
        <Text
          sx={{
            fontSize: [1, 2],
            mt: 3,
            flex: '1 0 auto',
          }}
        >
          {body}
        </Text>
        <Progress
          max={3}
          value={level}
          color={color}
          sx={{
            mt: 3,
            height: 5,
          }}
        />
        <Text
          sx={{
            fontSize: 1,
            marginTop: 2,
            color: color,
          }}
        >
          {display}
        </Text>
        {guest && (
          <Box
            sx={{
              fontSize: 1,
              mt: 3,
              mr: 'auto',
              bg: 'rgba(255, 255, 255, 0.2)',
              p: 2,
              color: 'text',
              fontWeight: 'bold',
            }}
          >
            Guest
          </Box>
        )}
      </motion.div>
    </Link>
  )
}

export default LectureCard
