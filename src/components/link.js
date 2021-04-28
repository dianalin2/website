/** @jsx jsx */
import { jsx } from 'theme-ui'
import { Link } from 'gatsby'

export default (props) => (
  <Link
    {...props}
    sx={{
      color: 'inherit',
      '&.active': {
        color: 'primary',
      },
    }}
  />
)
