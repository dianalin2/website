const fadeInUp = ({duration, y} = {}) => ({
  initial: {
    y: y ?? 20,
    opacity: 0,
  },
  animate: {
    y: 0,
    opacity: 1,
    transition: {
      duration: duration,
    }
  },
  exit: {
    y: y ?? 20,
    opacity: 0,
  }
})

const stagger  = ({duration} = {}) => ({
  animate: {
    transition: {
      staggerChildren: duration ?? 0.1
    }
  }
})

const cardAnimateProps = (isHoveringOverButtons = false) => ({
  whileHover: { scale: !isHoveringOverButtons ? 1.02 : 1 },
  whileTap: { scale: !isHoveringOverButtons ? 0.95 : 1 }
})

export {
  fadeInUp,
  stagger,
  cardAnimateProps
}
