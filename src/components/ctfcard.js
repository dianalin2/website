/** @jsx jsx */
import { Box, Heading, Link, Text, Button, jsx } from 'theme-ui'
import { useCallback, useState } from 'react'
import { motion } from 'framer-motion'

import ScoreBoard from './scoreboard'
import { cardAnimateProps } from '../animations/animations'
import datefmt from '../utils/datefmt'

const CTFCard = ({
  name,
  link,
  startDate,
  endDate,
  tjParticipants,
  ...props
}) => {
  const [modalOpen, setModalOpen] = useState(false)
  const [isHoveringOverButtons, setisHoveringOverButtons] = useState(false)

  const open = useCallback((e) => {
    e.preventDefault()
    setModalOpen(true)
  }, [])
  const close = useCallback(() => {
    setModalOpen(false)
  }, [])

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
        {...cardAnimateProps(isHoveringOverButtons)}
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
        }}
      >
        <Box>
          <Heading
            as='h1'
            sx={{
              fontSize: [3, 4, 5],
            }}
          >
            {name}
          </Heading>
          <Text
            sx={{
              fontSize: 1,
              marginTop: 2,
              color: 'primary',
            }}
          >
            {`${datefmt(startDate)} — ${datefmt(endDate)}`}
          </Text>
        </Box>
        {tjParticipants && (
          <Button
            onClick={open}
            onMouseEnter={() => {
              setisHoveringOverButtons(true)
            }}
            onMouseLeave={() => {
              setisHoveringOverButtons(false)
            }}
            sx={{
              mt: 4,
            }}
          >
            TJ Participants
          </Button>
        )}
        <ScoreBoard
          isOpen={modalOpen}
          scores={tjParticipants}
          onClose={close}
        />
      </motion.div>
    </Link>
  )
}

export default CTFCard
