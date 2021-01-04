/** @jsx jsx */
import { Box, Input, jsx } from 'theme-ui'
import { IoSearchSharp } from 'react-icons/io5'

const SearchBar = ({ onChange, value, type, text, placeholder, name, ...props }) => (
  <Box
    {...props}
    sx={{
      position: 'relative'
    }}
  >
    <IoSearchSharp
      sx={{
        position: 'absolute',
        marginTop: 'auto',
        marginBottom: 'auto',
        width: '3.5rem',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0
      }}
    />

    <Input
      onChange={onChange}
      type={type}
      value={value}
      placeholder={placeholder ?? 'Search'}
      sx={{
        bg: 'lightBackground',
        borderColor: 'transparent',
        paddingLeft: '3rem',
        fontFamily: 'body',
      }}
    >

    </Input>
  </Box>
)

export default SearchBar
