/** @jsx jsx */
import { Box, Heading, Text, Button, jsx } from 'theme-ui'
import { Global } from '@emotion/core'
import Modal from 'react-modal'

const columns = [
  {
    header: 'Rank',
    accessor: 'rank',
  },
  {
    header: 'Team',
    accessor: 'team',
  },
  {
    header: 'Score',
    accessor: 'score',
  },
]

const Table = ({ columns, data, ...props }) => {
  return (
    <table
      sx={{
        borderSpacing: '0 1em',
        borderCollapse: 'collapse',
        width: '100%',
      }}
      {...props}
    >
      <tbody>
        <tr
          sx={{
            borderBottom: '3px solid #ffffff20',
          }}
        >
          {columns.map((column, i) => (
            <td key={i}>
              <Heading
                sx={{
                  mt: 2,
                  mb: 2,
                }}
                as='h4'
                color='primary'
              >
                {column.header}
              </Heading>
            </td>
          ))}
        </tr>
        {data.map((obj, i) => (
          <tr
            key={i}
            sx={{
              border: 'solid #ffffff15',
              borderWidth: '3px 0',
              '&:last-child': {
                borderBottom: 'none',
              },
            }}
          >
            {columns.map((columnItem, j) => (
              <td key={j}>
                <Text
                  sx={{
                    mt: 2,
                    mb: 2,
                    mr: 3,
                  }}
                >
                  {obj[columnItem.accessor]}
                </Text>
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

Modal.setAppElement('#___gatsby')

const ScoreBoard = ({ scores, onClose, ...props }) => (
  <Modal
    {...props}
    className='modal-content'
    overlayClassName='modal-overlay'
    onRequestClose={onClose}
    closeTimeoutMS={125}
  >
    <Global
      styles={(theme) => ({
        '.modal-overlay': {
          zIndex: 1000,
          backgroundColor: 'rgba(0, 0, 0, 0.58)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          position: 'fixed',
          inset: 0,
          width: '100vw',
          height: '100vh',
        },
        '.modal-content': {
          minWidth: 260,
          maxWidth: 600,
          maxHeight: 800,
          padding: '2rem',
          borderRadius: 2,
          backgroundColor: theme.colors.lightBackground,
          position: 'relative',
          display: 'block',
          '&:focus': {
            outline: 'none',
          },
        },
        '.ReactModal__Overlay': {
          opacity: 0,
          transition: `all 125ms ease-in-out`,
        },
        '.ReactModal__Overlay--after-open': {
          opacity: 1,
        },
        '.ReactModal__Overlay--before-close': {
          opacity: 0,
        },
      })}
    />
    <Heading
      as='h1'
      sx={{
        fontSize: [3, 4, 5],
      }}
    >
      TJ Participants
    </Heading>
    <Box
      sx={{
        mt: 3,
        maxHeight: 400,
        overflow: 'auto',
      }}
    >
      <Table columns={columns} data={scores} />
    </Box>
    <Button
      sx={{
        mt: 3,
      }}
      onClick={onClose}
    >
      Close
    </Button>
  </Modal>
)

export default ScoreBoard
